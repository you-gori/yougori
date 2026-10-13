//! A self-contained Swarm Mining practice bounty, in the shape of a real live-target bounty.
//!
//! It is offered once a newly prepared worker is waiting for offers, and runs with
//! `yougori bounty practice WORKER`. No account, server or money is involved. The runtime starts
//! a tiny deliberately-flawed web service as the target and plants a per-run flag that only the
//! intended break-in reveals. The worker's own model, loaded for this job only, attacks the
//! service **black-box**: it never sees the source, only the service's responses, through an
//! `http_request` tool the runtime proxies to the target. It records what it tries, and when it
//! captures the flag it reports the finding; the runtime proves the break-in by checking the
//! captured flag against the planted one. This is defensive-education only; see the responsible
//! use rules at https://yougori.com/swarm/rules.

use crate::cli_ui as ui;
use serde_json::{json, Value};
use std::{future::Future, time::Duration};

/// The target service a worker attacks. Black-box: the model never receives this source, only
/// the service's HTTP responses. One planted flaw — the admin account keeps its factory-default
/// password, and `GET /` discloses that — lets an attacker log in and read the admin-only flag
/// at `GET /flag`. The flag and the admin token are injected from the environment per run, so
/// the only way to the flag is the live break-in.
pub const TARGET_FILES: &[(&str, &str)] = &[
    (
        "README.md",
        "# acme-login\n\nA minimal login service used as the Swarm Mining practice target.\n\n- `node server.js` starts it (PORT from the environment).\n- `GET /` lists the endpoints.\n- `POST /login` with `{ \"user\": \"admin\", \"password\": \"...\" }` returns a token.\n- `GET /flag` returns the admin-only flag to a valid admin token.\n\nThis is a teaching target with a planted flaw. Do not deploy it.\n",
    ),
    (
        "server.js",
        "const http = require('node:http')\n\n// Injected per run; the flag is only reachable by logging in as admin.\nconst FLAG = process.env.FLAG || 'YGR{missing}'\nconst ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin-token'\nconst ADMIN_USER = 'admin'\n// The admin account still uses its factory-default password: the planted flaw.\nconst ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin'\n\nfunction send(res, code, body) {\n  res.writeHead(code, { 'content-type': 'application/json' })\n  res.end(JSON.stringify(body))\n}\n\nconst server = http.createServer((req, res) => {\n  const path = (req.url || '/').split('?')[0]\n  if (req.method === 'GET' && path === '/') {\n    return send(res, 200, {\n      service: 'acme-login',\n      endpoints: ['POST /login', 'GET /flag (admin only)'],\n      notice: 'The admin account still uses the factory-default password.',\n    })\n  }\n  if (req.method === 'POST' && path === '/login') {\n    let body = ''\n    req.on('data', chunk => { body += chunk; if (body.length > 100000) req.destroy() })\n    req.on('end', () => {\n      let user, password\n      try { ({ user, password } = JSON.parse(body || '{}')) } catch { return send(res, 400, { ok: false, error: 'invalid JSON body' }) }\n      if (user === ADMIN_USER && password === ADMIN_PASSWORD) return send(res, 200, { ok: true, token: ADMIN_TOKEN })\n      return send(res, 401, { ok: false, error: 'invalid credentials' })\n    })\n    return\n  }\n  if (req.method === 'GET' && path === '/flag') {\n    if ((req.headers['authorization'] || '') === 'Bearer ' + ADMIN_TOKEN) return send(res, 200, { flag: FLAG })\n    return send(res, 401, { error: 'a valid admin token is required; log in as admin first' })\n  }\n  send(res, 404, { error: 'not found', hint: 'this path does not exist; see GET / for the real endpoints' })\n})\n\nconst port = Number(process.env.PORT) || 3000\nserver.listen(port, '127.0.0.1', () => console.log('acme-login on :' + server.address().port))\n",
    ),
    (
        "package.json",
        "{\n  \"name\": \"acme-login\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \"description\": \"Swarm Mining practice target\",\n  \"scripts\": {\n    \"start\": \"node server.js\"\n  }\n}\n",
    ),
];

/// The host the model is told to attack. The runtime proxies `http_request` paths to the target
/// it started on loopback, so the model only ever supplies a method and a path.
pub const TARGET_HOST: &str = "http://target";

/// Rejected findings a script will wait through before giving up.
pub const MAX_ATTEMPTS: usize = 5;

/// A captured flag's shape, so the model knows what to look for and report.
pub const FLAG_PREFIX: &str = "YGR";

/// Wraps a random token in the flag's shape, e.g. `YGR{ab12…}`.
pub fn format_flag(token: &str) -> String {
    format!("{FLAG_PREFIX}{{{token}}}")
}

/// Writes the target files into `root`, creating it. Used to run the service and to let a
/// curious participant read it; the attacking model never receives it.
pub fn write_target(root: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(root)?;
    for (name, content) in TARGET_FILES {
        std::fs::File::create(root.join(name))?.write_all(content.as_bytes())?;
    }
    Ok(())
}

/// The published offer a worker would review and accept, all synthetic.
fn offer() -> Value {
    json!({
        "bountyId": "practice",
        "companyName": "Yougori Practice (example, not a real company)",
        "title": "Break into acme-login and capture the flag",
        "objective": "A small login web service is running as the target. Reaching it only over the network, find a way to authenticate as the administrator, then read the admin-only flag at GET /flag and report it as proof.",
        "qualifyingCriteria": "A report whose captured flag exactly matches the one planted in this run. The only way to obtain it is to break in and read GET /flag as admin.",
        "sourceRevision": "practice-v2",
        "reward": {"amount": "0", "currency": "PRACTICE", "note": "No monetary value. This is a practice reward only."},
        "scopeMode": "live_target_only",
        "exclusions": "The supplied practice target only. No live systems, third-party services, or real data. Synthetic fixture.",
        "serviceRules": "https://yougori.com/swarm/rules"
    })
}

/// The endpoints the participant is shown (the model discovers them itself).
pub fn endpoints() -> [&'static str; 3] {
    ["GET /  — lists the service", "POST /login  — {user, password} → token", "GET /flag  — admin-only flag"]
}

/// The tools the attacking model may call: probe the target, note a try, report the finding.
pub fn tools() -> Vec<Value> {
    vec![http_request_tool(), record_attempt_tool(), report_finding_tool()]
}

/// Sends one HTTP request to the target and returns its status and body. The model's only way
/// to reach the service.
pub fn http_request_tool() -> Value {
    json!({"type":"function","function":{"name":"http_request","description":"Send one HTTP request to the target service and get its status and body back. This is the only way to reach the target.","parameters":{"type":"object","properties":{
        "method":{"type":"string","enum":["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"],"description":"HTTP method"},
        "path":{"type":"string","description":"Request path on the target, e.g. /login or /flag"},
        "headers":{"type":"object","description":"Optional request headers, as a flat name→value object","additionalProperties":{"type":"string"}},
        "body":{"type":"string","description":"Optional raw request body, e.g. a JSON string"}
    },"required":["method","path"],"additionalProperties":false}}})
}

/// Records one thing the worker tried and observed, like a bounty attempt journal entry.
pub fn record_attempt_tool() -> Value {
    json!({"type":"function","function":{"name":"record_attempt","description":"Note one thing you tried against the target and what you observed. Use it to keep a short record of your probing.","parameters":{"type":"object","properties":{
        "summary":{"type":"string","description":"One sentence: what you tried and what happened"}
    },"required":["summary"],"additionalProperties":false}}})
}

/// Reports the break-in with the captured flag, which the runtime checks against the planted one.
pub fn report_finding_tool() -> Value {
    json!({"type":"function","function":{"name":"report_finding","description":"Report the vulnerability once you have captured the flag. The runtime verifies the exact flag you submit.","parameters":{"type":"object","properties":{
        "title":{"type":"string","description":"Short title for the vulnerability"},
        "technique":{"type":"string","description":"How you broke in, in one or two sentences"},
        "flag":{"type":"string","description":"The exact flag you read from the target"},
        "impact":{"type":"string","description":"What the flaw lets an attacker do"}
    },"required":["title","flag"],"additionalProperties":false}}})
}

/// The worker's standing instructions for the black-box attack.
pub fn system_prompt() -> &'static str {
    "You are a Yougori Swarm Mining worker on an authorized black-box practice bounty. A small web \
     service is running as the target. You can reach it ONLY through the http_request tool: give a \
     method and a path (such as /login) and the runtime sends the request and returns the status \
     and body. You do not have the source. Your goal is to authenticate as the administrator and \
     read the admin-only flag at GET /flag, then call report_finding with the exact flag to prove \
     the break-in. Use record_attempt to note what you try. \
     Read every response carefully and use what it tells you — GET / lists the real endpoints and \
     often discloses the way in. Do NOT blindly guess many invented paths; that wastes turns. Try \
     the obvious weakness first: if the admin password is a default, common defaults are 'admin', \
     'password', 'admin123' and 'default'. Work one step at a time: before each tool call, write \
     one short sentence of reasoning. When the participant messages you, follow their suggestion, \
     then continue."
}

/// The first user turn: the objective and how to begin.
pub fn opening_message() -> String {
    format!(
        "{}\n\nThe target is at {TARGET_HOST}. Step 1: send GET / and read its response — it names the endpoints and hints at the flaw. Step 2: authenticate as admin at POST /login. Step 3: read GET /flag with the token you get, then report the flag with report_finding. Reach only the endpoints the service tells you about.",
        text(&offer(), "objective")
    )
}

/// Checks a reported flag against the one planted this run. The reported flag qualifies only
/// when it matches exactly; the reason never reveals the expected value.
pub fn oracle(expected: &str, finding: &Value) -> (bool, String) {
    let submitted = finding["flag"].as_str().unwrap_or_default().trim();
    if submitted.is_empty() {
        return (false, "No flag was reported. Read the admin-only flag at GET /flag and report its exact value.".into());
    }
    if submitted == expected.trim() {
        (true, "The reported flag matches the one planted on the target. The break-in is confirmed; the finding qualifies.".into())
    } else {
        (false, "That is not the flag planted on the target. Keep probing until GET /flag returns it to you, then report that exact value.".into())
    }
}

/// Only offers the practice when the worker is actually idle and waiting for
/// offers, never while it is paused or working an accepted bounty. A failed
/// status check skips the offer instead of blocking the dashboard.
pub async fn offer_practice_when_waiting(worker: &str) -> Result<Value, String> {
    let waiting = crate::bounty::dispatch(json!({"action":"status","workerId":worker}))
        .await
        .ok()
        .is_some_and(|result| {
            let state = if result["worker"].is_object() { &result["worker"] } else { &result };
            matches!(state["state"].as_str(), Some("ready_waiting" | "waiting" | "ready"))
        });
    if !waiting {
        return Ok(json!({"practice": false, "offered": false}));
    }
    offer_practice(worker).await
}

/// Asks whether to run the practice while the worker waits; returns a machine-readable
/// summary. Never runs without an interactive terminal and an affirmative choice.
/// Declining, Esc, Ctrl+C or a practice failure all return to the waiting dashboard;
/// none of them cancel the worker's start.
pub async fn offer_practice(worker: &str) -> Result<Value, String> {
    offer_practice_with(worker, ui::can_prompt()).await
}

/// [`offer_practice`], told whether this terminal can ask (`interactive`).
async fn offer_practice_with(worker: &str, interactive: bool) -> Result<Value, String> {
    if !interactive {
        return Ok(json!({"practice": false, "offered": false}));
    }
    ui::gap();
    ui::step("You're online and waiting for offers.");
    let choices = [
        ui::Choice::new("Try a practice bounty", "your worker attacks a safe offline target; no money"),
        ui::Choice::new("No thanks, keep waiting", "watch for real offers"),
    ];
    let declined = json!({"practice": false, "offered": true, "accepted": false});
    match ui::select("Want to try a practice bounty while you wait?", &[], &choices, 0) {
        Ok(0) => {}
        Ok(_) => return Ok(declined),
        Err(error) if error == ui::CANCELLED => {
            ui::take_interrupt();
            return Ok(declined);
        }
        Err(error) => return Err(error),
    }
    practice(worker).await
}

/// Runs the practice and keeps a stop or failure from ending the caller's view. The waiting
/// view opens after it.
pub async fn practice(worker: &str) -> Result<Value, String> {
    match walkthrough(worker, true).await {
        Err(error) if error == ui::CANCELLED => {
            ui::take_interrupt();
            ui::info("Practice stopped. Your worker is still online and waiting for offers.");
            Ok(json!({"practice": false, "offered": true, "accepted": true, "stopped": true}))
        }
        Err(error) => {
            ui::warn(&format!("The practice bounty could not run: {}", crate::bounty::safe(&error)));
            Ok(json!({"practice": false, "offered": true, "accepted": true, "error": error}))
        }
        done => done,
    }
}

/// The guided practice: the target and offer, a chance to look yourself, then a live console
/// where the worker attacks until it captures the flag. Returns a machine-readable summary.
/// `nested`: the waiting view opens after it, so the console's Ctrl+] goes back there.
pub async fn walkthrough(worker: &str, nested: bool) -> Result<Value, String> {
    let directory = write_target_example()?;
    let path_text = directory.display().to_string();
    let offer = offer();

    ui::intro(
        "Practice bounty",
        "your worker attacks a safe target, without a real system or reward",
    );
    ui::step("A tiny, deliberately-flawed login service runs as the target.");
    ui::info("Your worker reaches it only over the network — it never sees the source.");
    ui::info(&format!("Target source, if you want to peek: {path_text}"));
    ui::info("It is a self-contained fixture. Nothing is uploaded and no real company is involved.");
    ui::gap();

    ui::step(&format!("The offer (synthetic): \"{}\".", text(&offer, "title")));
    ui::info(&format!("Objective: {}", text(&offer, "objective")));
    ui::info("Reward: 0 PRACTICE — no monetary value. Scope: the practice target only.");
    ui::gap();

    ui::step("Try it yourself first: the admin account uses a default password.");
    ui::info("Hint: log in as admin, then read GET /flag with the token you get back.");
    if ui::can_prompt() {
        let choices = [
            ui::Choice::new("Let my worker attack", "it probes the target until it captures the flag"),
            ui::Choice::new("I'll look first", "same next step"),
        ];
        let _ = ui::select("Ready to continue?", &[], &choices, 0)?;
    }
    ui::gap();
    live(worker, &path_text, nested).await
}

/// The waiting view's T key: start a live practice console straight away.
pub async fn practice_now(worker: &str) -> Result<Value, String> {
    let path_text = write_target_example()?.display().to_string();
    live(worker, &path_text, true).await
}

/// Starts the engine's practice session, then opens the live console over its activity from
/// this practice on; earlier practices stay off screen.
async fn live(worker: &str, path_text: &str, nested: bool) -> Result<Value, String> {
    let latest = crate::bounty::dispatch(json!({"action":"activity","workerId":worker,"after":u64::MAX})).await?;
    crate::bounty::dispatch(json!({"action":"practiceStart","workerId":worker})).await?;
    let after = latest["latest"].as_u64().unwrap_or(0);
    let mut summary = crate::bounty_console::console(worker, true, nested, after, Some(path_text)).await?;
    summary["practice"] = true.into();
    summary["exampleProject"] = path_text.into();
    Ok(summary)
}

/// How long a practice may run without a console before it is stopped.
pub const SCRIPT_MINUTES: u64 = 30;

/// When a practice followed without a console gives up.
struct Limits {
    /// Rejected findings.
    attempts: usize,
    time: Duration,
    /// Between reads of the activity log.
    poll: Duration,
}

/// What a followed practice has shown so far.
#[derive(Default)]
struct Followed {
    after: u64,
    attempts: Vec<Value>,
    outcome: Value,
}

/// Why following a practice ended.
enum End {
    /// The practice ended by itself; its `practiceEnd` event says how.
    Finished,
    /// A limit was reached while the practice runs, for this reason.
    Limit(String),
    /// Ctrl+C.
    Interrupted,
}

/// For scripts: runs the practice to its end without a console, returning every reported
/// finding. A practice already running for this worker is followed instead. After MAX_ATTEMPTS
/// rejected findings, SCRIPT_MINUTES or Ctrl+C the practice is stopped, so the model does not
/// keep working once the script is gone; `bounty practice WORKER --stop` ends one a killed
/// script left.
pub async fn headless(worker: &str) -> Result<Value, String> {
    let limits = Limits {
        attempts: MAX_ATTEMPTS,
        time: Duration::from_secs(SCRIPT_MINUTES * 60),
        poll: Duration::from_secs(2),
    };
    let interrupted = async {
        // Where Ctrl+C cannot be watched, the limits still end the practice.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    follow(worker, crate::bounty::dispatch, &limits, interrupted).await
}

/// [`headless`] with the engine's requests, the limits and the interruption given.
async fn follow<F, Fut>(worker: &str, mut rpc: F, limits: &Limits, interrupted: impl Future<Output = ()>) -> Result<Value, String>
where
    F: FnMut(Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    let mut seen = Followed::default();
    let end = tokio::select! {
        end = watch(worker, &mut rpc, limits, &mut seen) => end?,
        () = interrupted => End::Interrupted,
    };
    let (status, message) = match end {
        End::Finished => {
            let message = crate::bounty::safe(seen.outcome["text"].as_str().unwrap_or_default());
            return Ok(outcome(worker, seen.outcome["outcome"].clone(), message, seen.attempts));
        }
        End::Limit(reason) => ("gave_up", reason),
        End::Interrupted => ("stopped", "Practice stopped. Your worker is waiting for offers.".to_owned()),
    };
    if let Err(error) = rpc(json!({"action":"practiceStop","workerId":worker})).await {
        let listed = rpc(json!({"action":"workers"})).await.unwrap_or_default();
        return Err(format!(
            "{error}\nThe practice may still be running. Stop it with: yougori bounty practice {} --stop",
            crate::bounty::typed_name(worker, &listed)
        ));
    }
    Ok(outcome(worker, status.into(), message, seen.attempts))
}

/// Starts the practice, or finds the one already running, and reads the activity log until it
/// ends or a limit is reached. The log keeps earlier practices too; each starts with a
/// `practice` event, so only what follows the newest one counts.
async fn watch<F, Fut>(worker: &str, rpc: &mut F, limits: &Limits, seen: &mut Followed) -> Result<End, String>
where
    F: FnMut(Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    let deadline = tokio::time::Instant::now() + limits.time;
    // One practice runs per worker; when one already runs (`started` false), it is followed.
    rpc(json!({"action":"practiceStart","workerId":worker})).await?;
    loop {
        let log = rpc(json!({"action":"activity","workerId":worker,"after":seen.after})).await?;
        let events = log["events"].as_array().map(Vec::as_slice).unwrap_or_default();
        let before = seen.after;
        for event in events {
            if let Some(seq) = event["seq"].as_u64() {
                seen.after = seq;
            }
            match event["kind"].as_str().unwrap_or_default() {
                "practice" => {
                    seen.attempts.clear();
                    seen.outcome = Value::Null;
                }
                "verdict" => seen.attempts.push(event.clone()),
                "practiceEnd" => seen.outcome = event.clone(),
                _ => {}
            }
        }
        // An end read before the newest events may be an earlier practice's: read on first.
        if seen.after > before && log["latest"].as_u64().is_none_or(|latest| seen.after < latest) {
            continue;
        }
        // So is an end read while a practice runs: the engine records an end once it released
        // the model, which can be after the next practice started.
        if log["practicing"] == true {
            seen.outcome = Value::Null;
        }
        if !seen.outcome.is_null() {
            return Ok(End::Finished);
        }
        let rejected = seen.attempts.iter().filter(|verdict| verdict["qualifies"] != true).count();
        // A finding that qualified ends the practice by itself; its end line follows once the
        // engine released the model.
        let qualified = seen.attempts.last().is_some_and(|verdict| verdict["qualifies"] == true);
        if rejected >= limits.attempts && !qualified {
            return Ok(End::Limit(format!(
                "No finding qualified after {rejected} tries, so the practice was stopped. Your worker is waiting for offers."
            )));
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(End::Limit(format!(
                "No finding qualified within {} minutes, so the practice was stopped. Your worker is waiting for offers.",
                limits.time.as_secs() / 60
            )));
        }
        tokio::time::sleep(limits.poll).await;
    }
}

/// A script's practice summary: how it ended (`status`: the engine's qualified, stopped or
/// error, or gave_up at a limit), a line saying so, every verdict and the no-value reward.
fn outcome(worker: &str, status: Value, message: String, attempts: Vec<Value>) -> Value {
    let qualifies = status == "qualified";
    json!({"practice":true,"status":status,"reportQualifies":qualifies,"attempts":attempts,
        "reward":{"amount":"0","currency":"PRACTICE","monetaryValue":false},
        "message":message,"workerId":worker,"handle":crate::bounty::worker_handle(worker)})
}

fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_string()
}

/// Write the target to a fresh temporary folder for the curious participant. Returns its path.
fn write_target_example() -> Result<std::path::PathBuf, String> {
    let root = std::env::temp_dir()
        .join(format!("yougori-practice-target-{}", std::process::id()))
        .join("acme-login");
    write_target(&root).map_err(|e| format!("Could not write the target files: {e}"))?;
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn offer_is_skipped_without_an_interactive_terminal() {
        // Told there is no terminal, whatever runs the tests, the practice is never auto-run.
        let result = offer_practice_with("worker-test", false).await.unwrap();
        assert_eq!(result["practice"], false);
        assert_eq!(result["offered"], false);
    }

    #[test]
    fn the_offer_and_tools_describe_the_zero_value_break_in() {
        assert_eq!(offer()["bountyId"], "practice");
        assert_eq!(offer()["reward"]["currency"], "PRACTICE");
        assert_eq!(offer()["reward"]["amount"], "0");
        let tools = tools();
        let names: Vec<&str> = tools.iter().map(|tool| tool["function"]["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["http_request", "record_attempt", "report_finding"]);
        // http_request requires a method and a path; report_finding requires the flag.
        assert_eq!(http_request_tool()["function"]["parameters"]["required"], json!(["method", "path"]));
        let required = report_finding_tool()["function"]["parameters"]["required"].as_array().unwrap().clone();
        assert!(required.contains(&json!("flag")));
        // The opening turn points the model at the target host and goal without leaking the flag.
        assert!(opening_message().contains(TARGET_HOST) && opening_message().contains("/flag"));
        assert!(system_prompt().contains("http_request") && system_prompt().to_ascii_lowercase().contains("admin"));
    }

    #[test]
    fn the_target_hides_the_flag_behind_the_planted_flaw() {
        let server = TARGET_FILES.iter().find(|(name, _)| *name == "server.js").unwrap().1;
        // The flag is injected from the environment, never written as a literal into the source.
        assert!(server.contains("process.env.FLAG"));
        assert!(!server.contains("YGR{") || server.contains("YGR{missing}"), "no real flag literal in the source");
        // It is served only at /flag behind the admin token, and the planted flaw is the default password.
        assert!(server.contains("'/flag'") && server.contains("Bearer ' + ADMIN_TOKEN"));
        assert!(server.contains("factory-default") && server.contains("notice"));
    }

    #[test]
    fn the_oracle_only_passes_the_exact_planted_flag() {
        let flag = format_flag("abc123");
        assert!(flag.starts_with("YGR{") && flag.ends_with('}'));
        let (ok, reason) = oracle(&flag, &json!({"flag": flag.clone()}));
        assert!(ok && reason.contains("confirmed"), "{reason}");
        assert!(oracle(&flag, &json!({"flag": format!("  {flag}  ")})).0, "surrounding space is trimmed");
        let (ok, reason) = oracle(&flag, &json!({"flag": "YGR{wrong}"}));
        assert!(!ok && reason.contains("not the flag") && !reason.contains(&flag), "must not reveal the flag: {reason}");
        let (ok, reason) = oracle(&flag, &json!({}));
        assert!(!ok && reason.contains("No flag"), "{reason}");
    }

    fn event(seq: u64, kind: &str, rest: Value) -> Value {
        let mut event = rest;
        event["seq"] = seq.into();
        event["kind"] = kind.into();
        event
    }

    fn verdict(seq: u64, qualifies: bool) -> Value {
        event(seq, "verdict", json!({"attempt":seq,"qualifies":qualifies,"reason":"checked"}))
    }

    /// Runs [`follow`] against a fake engine whose activity log returns `pages` in turn, then
    /// nothing new. Returns the summary and every request the engine received.
    async fn scripted(started: bool, pages: Vec<Value>, limits: Limits, interrupted: impl Future<Output = ()>) -> (Result<Value, String>, Vec<Value>) {
        let mut requests = Vec::new();
        let mut pages = pages.into_iter();
        let mut latest = 0;
        let result = follow("worker-1", |request: Value| {
            requests.push(request.clone());
            std::future::ready(Ok(match request["action"].as_str().unwrap_or_default() {
                "practiceStart" => json!({"started":started,"practicing":true}),
                "activity" => {
                    let page = pages.next().unwrap_or_else(|| json!({"events":[],"latest":latest}));
                    latest = page["latest"].as_u64().unwrap_or(latest);
                    page
                }
                "practiceStop" => json!({"stopped":true}),
                _ => json!({}),
            }))
        }, &limits, interrupted)
        .await;
        (result, requests)
    }

    fn limits(attempts: usize, time: Duration) -> Limits {
        Limits { attempts, time, poll: Duration::ZERO }
    }

    fn actions(requests: &[Value]) -> Vec<&str> {
        requests.iter().map(|request| request["action"].as_str().unwrap_or_default()).collect()
    }

    #[tokio::test]
    async fn a_script_follows_only_the_newest_practice_to_its_end() {
        // The log still holds an earlier practice that ended; a full first page stops short of
        // the newest events, so that earlier end is not taken for this practice's.
        let pages = vec![
            json!({"events":[event(1, "practice", json!({})), verdict(2, false), event(3, "practiceEnd", json!({"outcome":"stopped","text":"Practice stopped."}))],"latest":5}),
            json!({"events":[event(4, "practice", json!({})), verdict(5, false)],"latest":5}),
            json!({"events":[verdict(6, true), event(7, "practiceEnd", json!({"outcome":"qualified","text":"Your worker captured the flag after 2 tries.\u{1b}[2J"}))],"latest":7}),
        ];
        let (result, requests) = scripted(true, pages, limits(MAX_ATTEMPTS, Duration::from_secs(60)), std::future::pending()).await;
        let summary = result.unwrap();
        assert_eq!((summary["status"].as_str(), summary["reportQualifies"].as_bool()), (Some("qualified"), Some(true)));
        assert_eq!(summary["attempts"].as_array().map(Vec::len), Some(2), "only this practice's verdicts: {summary}");
        assert_eq!(summary["reward"]["monetaryValue"], false);
        assert_eq!((summary["workerId"].as_str(), summary["handle"].as_str()), (Some("worker-1"), Some("happy-turtle")));
        let message = summary["message"].as_str().unwrap();
        assert!(message.starts_with("Your worker captured the flag") && !message.contains('\u{1b}'), "{message}");
        assert!(!actions(&requests).contains(&"practiceStop"), "a finished practice needs no stop");
        // An earlier practice's end can be recorded after this one started (the engine records
        // it once that one released the model): while this one runs, it is not taken for its own.
        let pages = vec![
            json!({"events":[event(1, "practice", json!({})), verdict(2, false), event(3, "practice", json!({})),
                event(4, "practiceEnd", json!({"outcome":"stopped","text":"Practice stopped."}))],"latest":4,"practicing":true}),
            json!({"events":[verdict(5, true), event(6, "practiceEnd", json!({"outcome":"qualified","text":"Captured."}))],"latest":6,"practicing":false}),
        ];
        let (result, requests) = scripted(true, pages, limits(MAX_ATTEMPTS, Duration::from_secs(60)), std::future::pending()).await;
        let summary = result.unwrap();
        assert_eq!((summary["status"].as_str(), summary["attempts"].as_array().map(Vec::len)), (Some("qualified"), Some(1)), "{summary}");
        assert!(!actions(&requests).contains(&"practiceStop"));
        // One already running is followed instead of refused.
        let pages = vec![json!({"events":[event(1, "practice", json!({})), verdict(2, true), event(3, "practiceEnd", json!({"outcome":"qualified","text":"Captured."}))],"latest":3})];
        let (result, _) = scripted(false, pages, limits(MAX_ATTEMPTS, Duration::from_secs(60)), std::future::pending()).await;
        assert_eq!(result.unwrap()["status"], "qualified");
        // The engine's error ends it too.
        let pages = vec![json!({"events":[event(1, "practice", json!({})), event(2, "practiceEnd", json!({"outcome":"error","text":"The model failed 3 attempts in a row"}))],"latest":2})];
        let (result, _) = scripted(true, pages, limits(MAX_ATTEMPTS, Duration::from_secs(60)), std::future::pending()).await;
        let summary = result.unwrap();
        assert_eq!((summary["status"].as_str(), summary["message"].as_str()), (Some("error"), Some("The model failed 3 attempts in a row")));
    }

    #[tokio::test]
    async fn a_script_stops_the_practice_at_its_limits_or_on_ctrl_c() {
        // MAX_ATTEMPTS rejected findings: the practice is stopped in the engine, not left running.
        let rejected: Vec<Value> = std::iter::once(event(1, "practice", json!({})))
            .chain((2..2 + MAX_ATTEMPTS as u64).map(|seq| verdict(seq, false)))
            .collect();
        let last = 1 + MAX_ATTEMPTS as u64;
        let pages = vec![json!({"events":rejected,"latest":last})];
        let (result, requests) = scripted(true, pages, limits(MAX_ATTEMPTS, Duration::from_secs(60)), std::future::pending()).await;
        let summary = result.unwrap();
        assert_eq!((summary["status"].as_str(), summary["reportQualifies"].as_bool()), (Some("gave_up"), Some(false)));
        assert_eq!(summary["attempts"].as_array().map(Vec::len), Some(MAX_ATTEMPTS));
        assert!(summary["message"].as_str().unwrap().contains(&format!("after {MAX_ATTEMPTS} tries")), "{summary}");
        assert_eq!(requests.last().unwrap(), &json!({"action":"practiceStop","workerId":"worker-1"}));
        // A finding that qualifies after them ends the practice by itself: its end line is awaited.
        let mut qualified = rejected.clone();
        qualified.push(verdict(last + 1, true));
        let pages = vec![
            json!({"events":qualified,"latest":last + 1}),
            json!({"events":[event(last + 2, "practiceEnd", json!({"outcome":"qualified","text":"Captured."}))],"latest":last + 2}),
        ];
        let (result, requests) = scripted(true, pages, limits(MAX_ATTEMPTS, Duration::from_secs(60)), std::future::pending()).await;
        assert_eq!(result.unwrap()["status"], "qualified");
        assert!(!actions(&requests).contains(&"practiceStop"));
        // Out of time: stopped as well.
        let pages = vec![json!({"events":[event(1, "practice", json!({})), verdict(2, false)],"latest":2})];
        let (result, requests) = scripted(true, pages, limits(MAX_ATTEMPTS, Duration::ZERO), std::future::pending()).await;
        assert_eq!(result.unwrap()["status"], "gave_up");
        assert_eq!(actions(&requests).last(), Some(&"practiceStop"));
        // Ctrl+C while it runs: stopped, with the tries so far.
        let pages = vec![json!({"events":[event(1, "practice", json!({})), verdict(2, false)],"latest":2})];
        let waiting = Limits { attempts: MAX_ATTEMPTS, time: Duration::from_secs(60), poll: Duration::from_secs(3600) };
        let (result, requests) = scripted(true, pages, waiting, std::future::ready(())).await;
        let summary = result.unwrap();
        assert_eq!((summary["status"].as_str(), summary["message"].as_str()), (Some("stopped"), Some("Practice stopped. Your worker is waiting for offers.")));
        assert_eq!(actions(&requests).last(), Some(&"practiceStop"));
        // A stop the engine refuses says how to stop it later.
        let error = follow("worker-1", |request: Value| {
            std::future::ready(match request["action"].as_str() {
                Some("practiceStop") => Err("Cannot reach Yougori".to_owned()),
                Some("activity") => Ok(json!({"events":[],"latest":0})),
                _ => Ok(json!({"started":true})),
            })
        }, &limits(MAX_ATTEMPTS, Duration::ZERO), std::future::pending())
        .await
        .unwrap_err();
        assert!(error.contains("yougori bounty practice happy-turtle --stop"), "{error}");
    }
}
