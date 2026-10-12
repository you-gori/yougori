//! A self-contained Swarm Mining practice bounty.
//!
//! It is offered once a newly prepared worker is waiting for offers, and runs with
//! `yougori bounty practice WORKER`. No account, server or money is involved. It
//! writes a tiny deliberately-flawed Node project to a temporary folder and lets
//! you try to crack it yourself. Then the worker's own model, loaded for this job
//! only, investigates the same files and records a report through a function call.
//! The report is checked against the planted flaw and, when it qualifies, credited
//! as a no-value practice award. This is defensive-education only; see the
//! responsible use rules at https://yougori.com/swarm/rules.

use crate::cli_ui as ui;
use serde_json::{json, Value};

/// The example project a worker would receive. One planted flaw: the password is
/// compared against a hardcoded literal in the source, so anyone reading the file
/// can log in as the admin. The source does not label the flaw, so the user can
/// try to find it themselves.
const EXAMPLE_FILES: &[(&str, &str)] = &[
    (
        "README.md",
        "# practice-login\n\nA minimal login service for the Swarm Mining practice bounty.\n\n- `node server.js` starts it on port 3000.\n- `POST /login` with `{ \"user\": \"admin\", \"password\": \"...\" }`.\n- `npm test` runs the offline check.\n\nThis is a teaching fixture with a planted flaw. Do not deploy it.\n",
    ),
    (
        "auth.js",
        "// Checks a login for the practice service.\nconst ADMIN_USER = 'admin'\nconst ADMIN_PASSWORD = 'correct-horse-battery-staple'\n\nfunction authenticate(user, password) {\n  return user === ADMIN_USER && password === ADMIN_PASSWORD\n}\n\nmodule.exports = { authenticate }\n",
    ),
    (
        "server.js",
        "const http = require('node:http')\nconst { authenticate } = require('./auth')\n\nconst server = http.createServer((req, res) => {\n  if (req.method !== 'POST' || req.url !== '/login') {\n    res.writeHead(404).end('not found')\n    return\n  }\n  let body = ''\n  req.on('data', chunk => { body += chunk })\n  req.on('end', () => {\n    let user, password\n    try {\n      ({ user, password } = JSON.parse(body))\n    } catch {\n      res.writeHead(400).end('bad request')\n      return\n    }\n    const ok = authenticate(user, password)\n    res.writeHead(ok ? 200 : 401, { 'content-type': 'application/json' })\n    res.end(JSON.stringify({ ok }))\n  })\n})\n\nserver.listen(3000, () => console.log('practice-login on :3000'))\n",
    ),
    (
        "test.js",
        "// Offline check: a correct login is accepted, a wrong one is rejected.\nconst assert = require('node:assert')\nconst { authenticate } = require('./auth')\n\nassert.equal(authenticate('admin', 'correct-horse-battery-staple'), true)\nassert.equal(authenticate('admin', 'wrong'), false)\nassert.equal(authenticate('guest', 'correct-horse-battery-staple'), false)\n\nconsole.log('ok')\n",
    ),
    (
        "package.json",
        "{\n  \"name\": \"practice-login\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \"description\": \"Swarm Mining practice bounty fixture\",\n  \"scripts\": {\n    \"start\": \"node server.js\",\n    \"test\": \"node test.js\"\n  }\n}\n",
    ),
];

/// The published offer a worker would review and accept, all synthetic.
fn offer() -> Value {
    json!({
        "bountyId": "practice",
        "companyName": "Yougori Practice (example, not a real company)",
        "title": "Find the authentication flaw in practice-login",
        "objective": "A small Node login service is supplied as a local snapshot. Find a flaw that lets someone authenticate as the admin without being given the password, and report it with evidence.",
        "qualifyingCriteria": "A report that identifies a concrete, reproducible way to authenticate as admin from the supplied source, names the exact file and line, and shows the planted flaw.",
        "sourceRevision": "practice-v1",
        "reward": {"amount": "0", "currency": "PRACTICE", "note": "No monetary value. This is a practice reward only."},
        "scopeMode": "local_source_only",
        "exclusions": "Local supplied snapshot and offline checks only. No live systems, third-party services, or real data. Synthetic fixture.",
        "serviceRules": "https://yougori.com/swarm/rules"
    })
}

/// The 1-based line in auth.js that holds the hardcoded password, read from the
/// bundled source so the report can never point at the wrong line.
fn password_line() -> usize {
    let auth = EXAMPLE_FILES
        .iter()
        .find(|(name, _)| *name == "auth.js")
        .map(|(_, content)| *content)
        .unwrap_or_default();
    auth.lines()
        .position(|line| line.starts_with("const ADMIN_PASSWORD"))
        .map_or(0, |index| index + 1)
}

/// A qualifying report for this bounty, the reference for `verify`.
#[cfg(test)]
fn report() -> Value {
    let line = password_line();
    json!({
        "title": "Hardcoded admin password in auth.js",
        "component": "auth.js",
        "file": "auth.js",
        "line": line,
        "sourceRevision": "practice-v1",
        "reproduction": format!("Open auth.js. The admin password is assigned to ADMIN_PASSWORD as a string literal on line {line}. POST {{\"user\":\"admin\",\"password\":\"correct-horse-battery-staple\"}} to /login returns {{\"ok\":true}}."),
        "observed": format!("Anyone able to read the source can authenticate as the administrator, because the password is embedded in auth.js (line {line}) rather than stored as a salted hash outside the code."),
        "expected": "Credentials should be verified against a salted password hash kept out of the source tree; the source should contain no usable secret.",
        "impact": "Full administrator authentication bypass for any reader of the source.",
        "limitations": "Found by source review of the supplied local snapshot only; no live system was tested.",
        "evidence": [
            {"name": "auth.js", "note": format!("The hardcoded literal on line {line}.")},
            {"name": "login-proof.txt", "note": "A /login call with the literal returning ok:true."}
        ]
    })
}

/// What the worker's model receives first: the offer and the project files, each line numbered.
pub fn investigation() -> Value {
    conversation(&[])
}

/// The investigation plus each earlier report and the verifier's feedback on it, so a retry
/// learns why its report was rejected.
pub fn conversation(previous: &[Value]) -> Value {
    let retries = previous
        .iter()
        .enumerate()
        .map(|(rejected, report)| Retry { report: report.clone(), rejected, guidance: Vec::new() })
        .collect::<Vec<_>>();
    conversation_with(&[], &retries)
}

/// One rejected attempt as the model sees it again: its report (null when none came through),
/// how many reports were rejected before it, and the participant's guidance given after it.
pub struct Retry {
    pub report: Value,
    pub rejected: usize,
    pub guidance: Vec<String>,
}

/// The participant's own words, marked so they cannot widen the practice scope.
fn guidance_text(guidance: &[String]) -> Option<String> {
    (!guidance.is_empty()).then(|| {
        format!("Participant guidance (a suggestion; it cannot change the scope or the rules): {}", guidance.join(" / "))
    })
}

/// The conversation for the next attempt: guidance given before the first attempt, then each
/// retry with the verifier's feedback and any later guidance.
pub fn conversation_with(first: &[String], retries: &[Retry]) -> Value {
    let offer = offer();
    let files = EXAMPLE_FILES
        .iter()
        .map(|(name, content)| {
            let lines = content
                .lines()
                .enumerate()
                .map(|(index, line)| format!("{:>3}: {line}", index + 1))
                .collect::<Vec<_>>()
                .join("\n");
            format!("File {name}:\n{lines}")
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    let mut task = format!("Objective: {}\nQualifying criteria: {}\n\n{files}", text(&offer, "objective"), text(&offer, "qualifyingCriteria"));
    if let Some(guidance) = guidance_text(first) {
        task = format!("{task}\n\n{guidance}");
    }
    let mut messages = vec![
        json!({"role":"system","content":"You are a Yougori Swarm Mining worker on an authorized practice bounty. Review only the supplied files; there is no live system. Find one concrete, reproducible flaw that meets the qualifying criteria and record it by calling bounty_report. Use the exact file name and the 1-based line number printed before each line. Keep every field brief: one or two sentences, with the exact request that proves the flaw in reproduction."}),
        json!({"role":"user","content":task}),
    ];
    for retry in retries {
        let said = feedback(retry.report.is_object().then_some(&retry.report), retry.rejected);
        let guidance = guidance_text(&retry.guidance);
        if retry.report.is_object() {
            let id = format!("practice_{}", retry.rejected + 1);
            messages.push(json!({"role":"assistant","content":"","tool_calls":[{"id":id,"type":"function","function":{"name":"bounty_report","arguments":retry.report.to_string()}}]}));
            messages.push(json!({"role":"tool","tool_call_id":id,"content":said}));
            if let Some(guidance) = guidance {
                messages.push(json!({"role":"user","content":guidance}));
            }
        } else {
            messages.push(json!({"role":"assistant","content":"I did not record a report."}));
            let content = match guidance { Some(guidance) => format!("{said}\n\n{guidance}"), None => said };
            messages.push(json!({"role":"user","content":content}));
        }
    }
    Value::Array(messages)
}

/// The one function the model may call: its report, as a company would receive it.
pub fn report_tool() -> Value {
    json!({"type":"function","function":{"name":"bounty_report","description":"Record one evidenced finding for this practice bounty.","parameters":{"type":"object","properties":{
        "title":{"type":"string"},
        "file":{"type":"string","description":"Exact file name"},
        "line":{"type":"integer","description":"1-based line of the flaw"},
        "reproduction":{"type":"string","description":"Exact steps, including the request that proves the flaw"},
        "impact":{"type":"string"}
    },"required":["title","file","line","reproduction","impact"],"additionalProperties":false}}})
}

/// Attempts until a report qualifies, the first included.
pub const MAX_ATTEMPTS: usize = 5;

enum Verdict {
    Qualifies,
    WrongFile(String),
    WrongLine(Option<u64>),
    NotReproducible,
}

/// The qualifying criteria: the exact file and line of the planted flaw, and a reproduction
/// that actually logs in with the hardcoded password.
fn assess(report: &Value) -> Verdict {
    let file = report["file"].as_str().unwrap_or_default().trim().replace('\\', "/");
    let file = file.rsplit('/').next().unwrap_or_default();
    let line = report["line"].as_u64().or_else(|| report["line"].as_str().and_then(|line| line.trim().parse().ok()));
    let reproducible = ["reproduction", "title", "impact"]
        .iter()
        .any(|key| report[*key].as_str().is_some_and(|value| value.contains("correct-horse-battery-staple")));
    if !file.eq_ignore_ascii_case("auth.js") {
        Verdict::WrongFile(if file.is_empty() { "no file".into() } else { crate::bounty::safe(file) })
    } else if line != Some(password_line() as u64) {
        Verdict::WrongLine(line)
    } else if !reproducible {
        Verdict::NotReproducible
    } else {
        Verdict::Qualifies
    }
}

/// The verdict for the participant, who may see where the flaw is.
pub fn verify(report: &Value) -> (bool, String) {
    let expected = password_line();
    match assess(report) {
        Verdict::Qualifies => (true, format!("It names auth.js line {expected} and reproduces the admin login with the hardcoded password. It qualifies.")),
        Verdict::WrongFile(named) => (false, format!("It names {named}, not the file that holds the flaw. It does not qualify.")),
        Verdict::WrongLine(line) => {
            let named = line.map_or_else(|| "no line".to_string(), |line| format!("line {line}"));
            (false, format!("It names auth.js but {named}; the flaw is on line {expected}. It does not qualify."))
        }
        Verdict::NotReproducible => (false, format!("It names auth.js line {expected} but gives no login that reproduces it. It does not qualify.")),
    }
}

/// The verifier's feedback for the model's next attempt, after `rejected` earlier rejections.
/// It says why a report was rejected and, like a tutor, hints more each time, but never gives
/// the line number or the password.
pub fn feedback(report: Option<&Value>, rejected: usize) -> String {
    let reason = match report.map(assess) {
        None => "No report came through: the answer was cut off or did not call bounty_report. Call it once, with one short sentence per field.".to_string(),
        Some(Verdict::Qualifies) => return "Accepted: the report meets the qualifying criteria.".into(),
        Some(Verdict::WrongFile(named)) => format!("Rejected: {named} does not hold the flaw. Review the other files and call bounty_report again."),
        Some(Verdict::WrongLine(_)) => "Rejected: that line of auth.js is not where the flaw is. Find the exact line that gives away admin access and call bounty_report again.".into(),
        Some(Verdict::NotReproducible) => "Rejected: the reproduction does not log in as admin. Give the exact request that succeeds and call bounty_report again.".into(),
    };
    match rejected {
        0 => reason,
        1 => format!("{reason} Hint: the flaw is a secret written directly into the source, not the comparison logic."),
        _ => format!("{reason} Hint: auth.js assigns the admin password as a string literal. Report the line of that assignment, and log in with that exact password in reproduction."),
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
    if !ui::can_prompt() {
        return Ok(json!({"practice": false, "offered": false}));
    }
    ui::gap();
    ui::step("You're online and waiting for offers.");
    let choices = [
        ui::Choice::new("Try a practice bounty", "your worker investigates a safe offline example; no money"),
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

/// Runs the practice and keeps a stop or failure from ending the caller's view.
pub async fn practice(worker: &str) -> Result<Value, String> {
    match walkthrough(worker).await {
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

/// The guided practice: the example and offer, a chance to look yourself, then a live console
/// where the worker investigates until its report qualifies. Returns a machine-readable summary.
pub async fn walkthrough(worker: &str) -> Result<Value, String> {
    let directory = write_example()?;
    let path_text = directory.display().to_string();
    let offer = offer();

    ui::intro(
        "Practice bounty",
        "your worker on a safe example, without a real target or reward",
    );
    ui::step("A tiny, deliberately-flawed Node project was written for you to examine.");
    ui::info(&format!("Example project: {path_text}"));
    ui::info("Files: auth.js, server.js, test.js, package.json, README.md");
    ui::info("It is a self-contained fixture. Nothing is uploaded and no real company is involved.");
    ui::gap();

    ui::step(&format!("The offer (synthetic): \"{}\".", text(&offer, "title")));
    ui::info(&format!("Objective: {}", text(&offer, "objective")));
    ui::info("Reward: 0 PRACTICE — no monetary value. Scope: the local snapshot only.");
    ui::gap();

    ui::step("Try it yourself first: open auth.js and read the login check.");
    ui::info("Hint: a real service never ships a usable password in its source code.");
    if ui::can_prompt() {
        let choices = [
            ui::Choice::new("Let my worker investigate", "it keeps trying until its report qualifies"),
            ui::Choice::new("I'll read the code first", "same next step"),
        ];
        let _ = ui::select("Ready to continue?", &[], &choices, 0)?;
    }
    ui::gap();
    live(worker, &path_text).await
}

/// The waiting view's T key: start a live practice console straight away.
pub async fn practice_now(worker: &str) -> Result<Value, String> {
    let path_text = write_example()?.display().to_string();
    ui::step("Practice bounty: your worker investigates a safe offline example until its report qualifies.");
    ui::info(&format!("Example project: {path_text} · reward 0 PRACTICE, no money"));
    live(worker, &path_text).await
}

/// Starts the engine's practice session, then opens the live console over its activity.
async fn live(worker: &str, path_text: &str) -> Result<Value, String> {
    crate::bounty::dispatch(json!({"action":"practiceStart","workerId":worker})).await?;
    let mut summary = crate::bounty::console(worker, true).await?;
    summary["practice"] = true.into();
    summary["exampleProject"] = path_text.into();
    Ok(summary)
}

/// For scripts: run the practice to the end without a console, returning every attempt.
pub async fn headless(worker: &str) -> Result<Value, String> {
    let started = crate::bounty::dispatch(json!({"action":"practiceStart","workerId":worker})).await?;
    if started["started"] != true {
        return Err("A practice is already running for this worker".into());
    }
    let mut after = 0u64;
    let mut attempts: Vec<Value> = Vec::new();
    let mut outcome = Value::Null;
    loop {
        let log = crate::bounty::dispatch(json!({"action":"activity","workerId":worker,"after":after})).await?;
        for event in log["events"].as_array().into_iter().flatten() {
            if let Some(seq) = event["seq"].as_u64() {
                after = seq;
            }
            match event["kind"].as_str().unwrap_or_default() {
                "verdict" => attempts.push(event.clone()),
                "practiceEnd" => outcome = event.clone(),
                _ => {}
            }
        }
        if !outcome.is_null() && log["events"].as_array().is_none_or(|events| events.is_empty()) {
            let qualifies = outcome["outcome"] == "qualified";
            return Ok(json!({"practice":true,"status":outcome["outcome"],"reportQualifies":qualifies,
                "attempts":attempts,"reward":{"amount":"0","currency":"PRACTICE","monetaryValue":false}}));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_string()
}

/// Write the example project to a fresh temporary folder. Returns its path.
fn write_example() -> Result<std::path::PathBuf, String> {
    use std::io::Write;
    let base = std::env::temp_dir().join(format!(
        "yougori-practice-bounty-{}",
        std::process::id()
    ));
    let root = base.join("practice-login");
    std::fs::create_dir_all(&root).map_err(|e| format!("Could not create the example folder: {e}"))?;
    for (name, content) in EXAMPLE_FILES {
        let file = root.join(name);
        let mut handle = std::fs::File::create(&file)
            .map_err(|e| format!("Could not write {name}: {e}"))?;
        handle
            .write_all(content.as_bytes())
            .map_err(|e| format!("Could not write {name}: {e}"))?;
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn offer_is_skipped_without_an_interactive_terminal() {
        // Tests run without a TTY, so the practice is never auto-run.
        let result = offer_practice("worker-test").await.unwrap();
        assert_eq!(result["practice"], false);
        assert_eq!(result["offered"], false);
    }

    #[test]
    fn synthetic_offer_and_report_describe_the_zero_value_flaw() {
        assert_eq!(offer()["bountyId"], "practice");
        assert_eq!(offer()["reward"]["currency"], "PRACTICE");
        assert_eq!(offer()["reward"]["amount"], "0");
        // The report names the planted flaw's file.
        assert_eq!(report()["component"], "auth.js");
    }

    #[test]
    fn report_points_at_the_line_holding_the_hardcoded_password() {
        let auth = EXAMPLE_FILES
            .iter()
            .find(|(name, _)| *name == "auth.js")
            .unwrap()
            .1;
        let line = password_line();
        assert!(line > 0);
        let source_line = auth.lines().nth(line - 1).unwrap();
        assert!(source_line.contains("'correct-horse-battery-staple'"));
        let report = report();
        assert_eq!(report["line"], line);
        assert!(text(&report, "reproduction").contains(&format!("line {line}")));
        // The source does not label the flaw for the user.
        assert!(!auth.to_ascii_lowercase().contains("flaw"));
    }

    #[test]
    fn only_the_exact_file_line_and_a_working_login_qualify() {
        let mut found = json!({"title":"Hardcoded admin password","file":"auth.js","line":password_line(),
            "reproduction":"POST {\"user\":\"admin\",\"password\":\"correct-horse-battery-staple\"} to /login","impact":"Admin login"});
        assert!(verify(&found).0, "{}", verify(&found).1);
        assert!(verify(&report()).0, "the reference report qualifies");
        found["file"] = json!("practice-login\\auth.js");
        found["line"] = json!(password_line().to_string());
        assert!(verify(&found).0, "a folder prefix and a numeric string still name the line");
        for (key, value) in [("file", json!("server.js")), ("line", json!(2)), ("reproduction", json!("Log in as admin"))] {
            let mut wrong = found.clone();
            wrong[key] = value;
            let (qualifies, reason) = verify(&wrong);
            assert!(!qualifies && reason.contains("does not qualify"), "{key}: {reason}");
        }
        assert!(!verify(&json!({})).0);
        let messages = investigation();
        let files = messages[1]["content"].as_str().unwrap();
        assert!(files.contains(&format!("{:>3}: const ADMIN_PASSWORD", password_line())), "{files}");
        assert_eq!(report_tool()["function"]["name"], "bounty_report");
    }

    #[test]
    fn retries_get_the_reason_but_never_the_answer() {
        let wrong_line = json!({"title":"Bypass","file":"auth.js","line":6,"reproduction":"any password","impact":"admin"});
        let messages = conversation(&[wrong_line.clone(), Value::Null]);
        let roles: Vec<&str> = messages.as_array().unwrap().iter().map(|m| m["role"].as_str().unwrap()).collect();
        assert_eq!(roles, ["system", "user", "assistant", "tool", "assistant", "user"]);
        assert_eq!(messages[2]["tool_calls"][0]["id"], messages[3]["tool_call_id"]);
        let arguments: Value = serde_json::from_str(messages[2]["tool_calls"][0]["function"]["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(arguments, wrong_line);
        let line = password_line().to_string();
        for rejected in 0..MAX_ATTEMPTS {
            for report in [Some(&wrong_line), Some(&json!({"file":"server.js","line":1})), Some(&json!({"file":"auth.js","line":password_line()})), None] {
                let said = feedback(report, rejected);
                assert!(said.contains("bounty_report"), "{said}");
                assert!(!said.contains(&format!("line {line}")) && !said.contains("correct-horse-battery-staple"), "{said}");
                assert_eq!(said.contains("Hint:"), rejected > 0, "hints start after the first rejection: {said}");
            }
        }
        assert!(feedback(Some(&report()), 3).starts_with("Accepted"));
        assert_ne!(messages[3]["content"], messages[5]["content"], "the second rejection hints more");
        assert_eq!(investigation(), conversation(&[]));
    }

    #[test]
    fn writes_every_example_file_to_disk() {
        let root = write_example().unwrap();
        for (name, _) in EXAMPLE_FILES {
            assert!(root.join(name).is_file(), "missing {name}");
        }
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
    }
}
