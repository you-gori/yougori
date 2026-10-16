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
const RESPONSE_CLIP: usize = 16000;
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
        // A hacker's client: it keeps cookies across calls (a login sticks for later requests) and
        // does not auto-follow redirects, so the model sees each 3xx and its Location itself. The
        // base host is fixed to this loopback target, so the model can only ever reach the target.
        let client = reqwest::Client::builder()
            .no_proxy()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
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
            Ok((status, headers, text)) => {
                let shown: String = text.chars().take(RESPONSE_CLIP).collect();
                let truncated = shown.len() < text.len();
                serde_json::json!({"status":status,"headers":headers,"body":shown,"truncated":truncated})
            }
            Err(error) => serde_json::json!({"status":0,"error":error}),
        }
    }

    async fn send(&self, method: &str, path: &str, headers: &Value, body: Option<String>) -> Result<(u16, Value, String), String> {
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
        let headers = header_map(response.headers());
        let text = response.text().await.unwrap_or_default();
        Ok((status, headers, text))
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

/// The response headers as a flat name→value object, so the model can read cookies, redirect
/// targets, auth challenges, content types and the server banner. Repeated headers are joined and
/// long values clipped, so one response cannot flood the model's context.
fn header_map(headers: &reqwest::header::HeaderMap) -> Value {
    let mut map = serde_json::Map::new();
    for (name, value) in headers.iter().take(64) {
        let text: String = String::from_utf8_lossy(value.as_bytes()).chars().take(1024).collect();
        let key = name.as_str();
        let merged = match map.get(key).and_then(Value::as_str) {
            Some(prior) => format!("{prior}, {text}"),
            None => text,
        };
        map.insert(key.to_owned(), Value::String(merged));
    }
    Value::Object(map)
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

/// Model turns a live-target attack runs before it gives up. A real break-in chains several steps
/// (recon, enumerate, exploit, pivot to the flag), so give the model room to work.
const MAX_TURNS: usize = 100;
/// Output budget per turn: room for a reasoning model's thinking, a sentence of reasoning and one
/// tool call carrying a non-trivial request body.
const ATTACK_TOKENS: u64 = 4096;
/// How long the loop waits for a message the participant started typing and left.
const HOLD: Duration = Duration::from_secs(600);

/// The tools the attacking model may call against the live target: a full HTTP client, an attempt
/// journal, and the capture report.
fn tools() -> Vec<Value> {
    vec![
        http_request_tool(),
        yougori_cli::bounty_practice::record_attempt_tool(),
        yougori_cli::bounty_practice::report_finding_tool(),
    ]
}

/// A richer `http_request` than the practice fixture's: it documents that response headers come
/// back, that the session keeps cookies across calls, and that redirects are shown, not followed —
/// everything a real attacker relies on.
fn http_request_tool() -> Value {
    json!({"type":"function","function":{"name":"http_request","description":"Send one HTTP request to the target and get back its status, response headers and body. This is the only way to reach the target. Cookies the target sets are kept and sent automatically on later calls, so a login persists. Redirects are NOT followed: a 3xx returns its Location header for you to follow yourself. Set any request headers you need (Authorization, Cookie, Content-Type, X-Forwarded-For, Range, …) and any body.","parameters":{"type":"object","properties":{
        "method":{"type":"string","enum":["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"],"description":"HTTP method"},
        "path":{"type":"string","description":"Request path on the target, e.g. /login, /api/users/1, or /admin?debug=1"},
        "headers":{"type":"object","description":"Request headers as a flat name→value object","additionalProperties":{"type":"string"}},
        "body":{"type":"string","description":"Optional raw request body, e.g. a JSON string or form-encoded data"}
    },"required":["method","path"],"additionalProperties":false}}})
}

/// The worker's standing instructions for the authorized live-target attack: a full offensive
/// methodology, so the model behaves like a strong bug-bounty hunter rather than a path guesser.
fn system_prompt(policy: &Value) -> String {
    format!(
        "You are an elite offensive-security agent on an AUTHORIZED Yougori Swarm Mining bounty. The \
         publisher is running their own web service as the target and has explicitly authorized you \
         to attack it and capture a secret flag they planted - a value only a genuine break-in can \
         reach. This is legal, sanctioned penetration testing of the publisher's own system.\n\n\
         You reach the target ONLY through the http_request tool. It returns the status, response \
         headers and body; cookies persist across calls so a login sticks; redirects are not \
         followed, so read the Location header and follow it yourself.\n\n\
         Work like a top bug-bounty hunter. Be methodical, read every response - headers included - \
         closely, and let what you learn drive the next request:\n\
         1. Recon. GET / and probe for index pages, robots.txt, sitemap, /api, /.well-known, docs \
         and error pages. Fingerprint the stack from Server/X-Powered-By headers, cookies and error \
         text, and cross-reference the source you were given to find the real routes, parameters and \
         the actual flaw.\n\
         2. Map the surface. Enumerate endpoints, methods (try OPTIONS), parameters and the auth model.\n\
         3. Test every class that fits: broken authentication and default/weak credentials; broken \
         access control, IDOR/BOLA and forced browsing of admin routes; HTTP verb and header \
         tampering; injection (SQL, NoSQL, command, SSTI, XXE); path traversal / LFI; SSRF; insecure \
         deserialization; JWT and session flaws (alg:none, weak secret, tampering, fixation); mass \
         assignment; exposed debug/backup/secret endpoints; and information disclosure in errors or \
         headers.\n\
         4. Chain it. Use a leaked value, token, cookie or session to reach the protected flag.\n\
         5. Capture. When a response contains the flag, call report_finding with the EXACT flag text \
         and a clear technique. Journal each meaningful try with record_attempt so progress is kept.\n\n\
         Write one short sentence of reasoning before each tool call. Do not blindly guess invented \
         paths - let the responses and the source guide you. Stay strictly on this target over HTTP: \
         never touch the host, other systems, the filesystem, or the internet.\n\n\
         Objective: {}.\nQualifying criteria: {}.",
        policy["objective"].as_str().unwrap_or_default(),
        policy["qualifyingCriteria"].as_str().unwrap_or_default()
    )
}

/// A grey-box recon briefing built from the accepted source snapshot: the file list, then as much
/// readable source as fits a bounded budget. The participant accepted this exact snapshot, so the
/// attacker reads it to locate the flaw - it must still exploit the running service over HTTP to
/// capture the flag, which is what the publisher verifies.
fn source_briefing(files: &[(String, Vec<u8>)]) -> String {
    /// Total source bytes folded into the briefing, kept modest so it fits small model contexts.
    const TOTAL: usize = 24000;
    /// Per-file cap, so one large file cannot crowd out the rest.
    const PER_FILE: usize = 8000;
    let mut listing = String::new();
    for (path, bytes) in files {
        listing.push_str(&format!("- {path} ({} bytes)\n", bytes.len()));
    }
    let mut body = String::new();
    let mut used = 0usize;
    for (path, bytes) in files {
        if used >= TOTAL {
            body.push_str("\n… (remaining files listed above are not inlined; infer them from the routes you see)\n");
            break;
        }
        let Ok(text) = std::str::from_utf8(bytes) else { continue };
        if text.trim().is_empty() {
            continue;
        }
        let budget = PER_FILE.min(TOTAL - used);
        let shown: String = text.chars().take(budget).collect();
        used += shown.len();
        let tail = if shown.len() < text.len() { "\n… (truncated)\n" } else { "\n" };
        body.push_str(&format!("\n===== {path} =====\n{shown}{tail}"));
    }
    format!(
        "Authorized grey-box recon — the accepted source snapshot of the target. Read it to find the \
         flaw, then break in over the network to capture the flag.\n\nFiles:\n{listing}{body}"
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

    let outcome = attack(app, worker, cancel, &service, &lease, &spec.files).await;
    let _ = agent(app, worker, reqwest::Method::POST, "/api/swarm/agent/tasks/release",
        Some(json!({"leaseId":lease["leaseId"],"generation":lease["generation"],"reason":"Live-target attack finished","idempotencyKey":format!("live-release-{id}")}))).await;
    service.stop().await;
    outcome
}

/// The model attack loop against the live service. Records each try as an attempt and, on a
/// reported capture, files the report. Returns once it reports, gives up, or is cancelled.
async fn attack(app: &AppHandle, worker: &Worker, cancel: &CancellationToken, service: &Service, lease: &Value, files: &[(String, Vec<u8>)]) -> Result<(), String> {
    let id = &worker.id;
    let model = worker.model_environment_id.clone().ok_or("Missing model environment")?;
    let mut messages = vec![
        json!({"role":"system","content":system_prompt(&worker.policy)}),
        json!({"role":"user","content":source_briefing(files)}),
        json!({"role":"user","content":"The target is at http://target. Start with GET / to see what it exposes, cross-reference the source above, then work toward the flag. Report it with report_finding once you have read it."}),
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
            "tool_choice":"auto","temperature":if turn == 1 { 0.2 } else { 0.5 },"max_tokens":ATTACK_TOKENS,"stream":true});

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
