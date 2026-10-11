//! A self-contained Swarm Mining practice bounty.
//!
//! It is offered once a worker comes online and is waiting for offers, not as its
//! own command. It runs entirely offline: no model, no account, no server, no
//! money. It writes a tiny deliberately-flawed Node project to a temporary
//! folder, lets you try to crack it yourself, then replays exactly how a worker
//! investigates, records an evidenced report, and how that report is verified and
//! credited as a no-value practice award. It teaches the real flow without any
//! real target, reward, or payment. This is defensive-education only; see the
//! responsible use rules at https://yougori.com/swarm/rules.

use crate::cli_ui as ui;
use serde_json::{json, Value};
use std::time::Duration;

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

/// The evidenced report the worker would submit for this bounty.
fn report() -> Value {
    let line = password_line();
    json!({
        "title": "Hardcoded admin password in auth.js",
        "component": "auth.js",
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

fn pause(ms: u64) {
    if ui::can_prompt() {
        std::thread::sleep(Duration::from_millis(ms));
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
    offer_practice()
}

/// Asks whether to run the practice walkthrough while the worker waits; returns
/// a machine-readable summary. Never runs without an interactive terminal and an
/// affirmative choice. Declining, Esc, Ctrl+C or a practice failure all return to
/// the waiting dashboard; none of them cancel the worker's start.
pub fn offer_practice() -> Result<Value, String> {
    if !ui::can_prompt() {
        return Ok(json!({"practice": false, "offered": false}));
    }
    ui::gap();
    ui::step("You're online and waiting for offers.");
    let choices = [
        ui::Choice::new("Try a practice bounty", "a safe, offline example — no model or money"),
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
    match walkthrough() {
        Err(error) if error == ui::CANCELLED => {
            ui::take_interrupt();
            ui::info("Practice stopped. Your worker is still online and waiting for offers.");
            Ok(json!({"practice": false, "offered": true, "accepted": true, "stopped": true}))
        }
        Err(error) => {
            ui::warn(&format!("The practice bounty could not run: {error}"));
            Ok(json!({"practice": false, "offered": true, "accepted": true, "error": error}))
        }
        done => done,
    }
}

/// Run the guided offline walkthrough. Returns a machine-readable summary.
pub fn walkthrough() -> Result<Value, String> {
    let directory = write_example()?;
    let path_text = directory.display().to_string();
    let offer = offer();
    let line = password_line();

    ui::intro(
        "Practice bounty",
        "see the whole flow without a real target or reward",
    );
    ui::step("A tiny, deliberately-flawed Node project was written for you to examine.");
    ui::info(&format!("Example project: {path_text}"));
    ui::info("Files: auth.js, server.js, test.js, package.json, README.md");
    ui::info("It is a self-contained fixture. Nothing is uploaded and no real company is involved.");
    ui::gap();

    ui::step(&format!("The offer (synthetic): \"{}\".", text(&offer, "title")));
    ui::info(&format!("Objective: {}", text(&offer, "objective")));
    ui::info("Reward: 0 PRACTICE — no monetary value. Scope: the local snapshot and offline checks only.");
    ui::gap();

    ui::step("Try it yourself first: open auth.js and read the login check.");
    ui::info("Hint: a real service never ships a usable password in its source code.");
    if ui::can_prompt() {
        let choices = [
            ui::Choice::new("Show how a worker cracks it", ""),
            ui::Choice::new("I'll read the code first", "same next step"),
        ];
        let _ = ui::select("Ready to continue?", &[], &choices, 0)?;
    }
    ui::gap();

    ui::step("A worker accepts the exact terms, then investigates the approved snapshot.");
    pause(400);
    ui::info("1/3 · source review of auth.js");
    pause(500);
    ui::info(&format!("2/3 · found a hardcoded admin password literal (auth.js, line {line})"));
    pause(500);
    ui::info("3/3 · ran the declared offline check: a /login with that literal returns ok:true");
    pause(400);
    ui::gap();

    ui::step("The worker records an evidenced report (this is what the company receives):");
    let report = report();
    ui::info(&format!("Title: {}", text(&report, "title")));
    ui::info(&format!("Component: {}", text(&report, "component")));
    ui::info(&format!("Reproduction: {}", text(&report, "reproduction")));
    ui::info(&format!("Impact: {}", text(&report, "impact")));
    ui::info("Evidence: auth.js, login-proof.txt");
    ui::gap();

    ui::step("Verification checks the report against the qualifying criteria.");
    pause(500);
    ui::info("The report names the exact file and line and shows the planted flaw — it qualifies.");
    ui::gap();

    ui::step("Result: credited as a practice award.");
    ui::info("Practice reward: 0 PRACTICE · no monetary value · nothing is paid or owed.");
    ui::info("On a real bounty this is where a publisher-promised USDC reward would be recorded,");
    ui::info("then paid directly by the publisher outside Yougori. Yougori never holds or pays funds.");
    ui::gap();

    ui::step("Next: when a real offer arrives, review and accept it to work it for real.");
    ui::info("Browse offers from the waiting dashboard; your worker is still online.");
    ui::outro("Practice complete. The example project stays on disk for you to read.");

    Ok(json!({
        "practice": true,
        "status": "completed",
        "exampleProject": path_text,
        "reportQualifies": true,
        "reward": {"amount": "0", "currency": "PRACTICE", "monetaryValue": false},
    }))
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

    #[test]
    fn offer_is_skipped_without_an_interactive_terminal() {
        // Tests run without a TTY, so the practice is never auto-run.
        let result = offer_practice().unwrap();
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
    fn writes_every_example_file_to_disk() {
        let root = write_example().unwrap();
        for (name, _) in EXAMPLE_FILES {
            assert!(root.join(name).is_file(), "missing {name}");
        }
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
    }
}
