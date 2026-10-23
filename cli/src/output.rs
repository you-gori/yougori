use serde_json::Value;
use std::io::IsTerminal;

const RESET: &str = "\x1b[0m";
const BRAND: &str = "\x1b[1;96m";
const HEADING: &str = "\x1b[1m";
const MUTED: &str = "\x1b[2m";
const ACCENT: &str = "\x1b[94m";
const GOOD: &str = "\x1b[92m";
const WARN: &str = "\x1b[93m";
const BAD: &str = "\x1b[91m";

fn enabled(terminal: bool, no_color: Option<&str>, term: Option<&str>) -> bool {
    terminal && no_color.is_none_or(|value| value.is_empty())
        && !matches!(term, Some("dumb" | "xterm-mono"))
}

pub fn stdout_color() -> bool {
    enabled(std::io::stdout().is_terminal(), std::env::var("NO_COLOR").ok().as_deref(), std::env::var("TERM").ok().as_deref())
}

fn paint(output: &mut String, text: &str, color: &str) {
    output.push_str(color);
    output.push_str(text);
    output.push_str(RESET);
}

fn styled(text: &str, style: &str, color: bool) -> String {
    if color { format!("{style}{text}{RESET}") } else { text.to_owned() }
}

// Names and provider messages can come from guests or remote APIs. They must not
// be able to move the cursor, forge another row, or change the terminal theme.
fn safe(text: &str) -> String {
    text.chars().filter_map(|c| match c {
        '\n' | '\r' | '\t' => Some(' '),
        c if c.is_control() => None,
        c => Some(c),
    }).collect()
}

fn section(title: &str, color: bool) -> String {
    format!("{}\n", styled(&safe(&title.to_uppercase()), BRAND, color))
}

fn tone(value: &str) -> &'static str {
    match value.to_ascii_lowercase().as_str() {
        "running" | "ready" | "connected" | "healthy" | "ok" | "in use" | "active" | "published" | "live" | "working" => GOOD,
        "error" | "failed" | "fail" | "needs attention" | "unavailable" => BAD,
        "warning" | "warn" | "starting" | "stopping" | "pending" | "provisioning" | "preparing" | "preparing bounty" | "report ready" => WARN,
        _ => MUTED,
    }
}

pub fn json(value: &Value, color: bool) -> String {
    let plain = serde_json::to_string_pretty(value).unwrap();
    if !color { return plain; }
    // Tokenize the serializer's JSON, never the unescaped values themselves.
    // Removing our SGR sequences gives exactly the same JSON for every value.
    let bytes = plain.as_bytes();
    let mut output = String::with_capacity(plain.len());
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' => i += 2,
                        b'"' => { i += 1; break; }
                        _ => i += 1,
                    }
                }
                let key = plain[i..].trim_start().starts_with(':');
                paint(&mut output, &plain[start..i], if key { "\x1b[96m" } else { "\x1b[92m" });
            }
            b'-' | b'0'..=b'9' | b't' | b'f' | b'n' => {
                i += 1;
                while i < bytes.len() && !matches!(bytes[i], b',' | b']' | b'}' | b' ' | b'\r' | b'\n') { i += 1; }
                let token = &plain[start..i];
                paint(&mut output, token, match token {
                    "true" => "\x1b[92m", "false" => "\x1b[91m", "null" => "\x1b[90m", _ => "\x1b[93m",
                });
            }
            _ => { output.push(bytes[i] as char); i += 1; }
        }
    }
    output
}

pub fn help(text: &str, color: bool) -> String {
    if !color { return text.into(); }
    let mut output = String::with_capacity(text.len() + 240);
    output.push_str(&styled("  YOUGORI", BRAND, color));
    output.push_str("\n  ");
    output.push_str(&styled("Environments, models and Personal Vault on this computer", MUTED, color));
    output.push_str("\n\n");
    output.push_str(&section("Start here", color));
    for (command, description) in [
        ("yougori", "Open the main menu and add this project's shortcut"),
        ("yougori cli", "Choose actions from interactive menus"),
        ("yougori run nginx", "Create and start a container"),
        ("yougori status", "See environments and connections"),
        ("yougori doctor", "Check this computer"),
    ] {
        output.push_str("  ");
        output.push_str(&styled(command, HEADING, color));
        output.push_str("  ");
        output.push_str(&styled(description, MUTED, color));
        output.push('\n');
    }
    output.push('\n');
    for line in text.split_inclusive('\n') {
        let content = line.strip_suffix('\n').unwrap_or(line);
        if content.starts_with("Yougori —") {
            // The brand and subtitle above replace the old introductory line.
            continue;
        } else if content.starts_with("Yougori CLI") {
            output.push_str(&section("Advanced control", color));
        } else if content.ends_with(':') && !content.starts_with("  ") {
            output.push_str(&section(content.trim_end_matches(':'), color));
        } else if let Some(command) = content.strip_prefix("  ").filter(|line| {
            line.split_whitespace().next().is_some_and(|word| matches!(word,
                "yougori" | "app" | "env" | "connection" | "remote" | "share" | "ports" | "snapshot" | "backup" | "gpu" |
                "terminal" | "microvm" | "neocloud" | "agent" | "window" | "settings" | "jobs" | "skills" | "schema" | "call" | "cloud" | "domain" | "drives" | "project" | "lan" | "storage"))
        }) {
            let (usage, description) = command.split_once("  ").unwrap_or((command, ""));
            output.push_str("  ");
            paint(&mut output, usage, HEADING);
            if !description.is_empty() { output.push_str("  "); paint(&mut output, description, MUTED); }
        } else { output.push_str(content); }
        if line.ends_with('\n') { output.push('\n'); }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    fn without_sgr(text: &str) -> String {
        let mut output = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                assert_eq!(chars.next(), Some('['));
                for c in chars.by_ref() { if c == 'm' { break; } assert!(c.is_ascii_digit() || c == ';'); }
            } else { output.push(c); }
        }
        output
    }
    #[test]
    fn redirects_and_explicit_plain_text_preferences_never_receive_ansi() {
        for terminal in [false, true] {
            assert!(!enabled(terminal, Some("1"), Some("xterm-256color")));
            assert!(!enabled(terminal, None, Some("dumb")));
        }
        assert!(!enabled(false, None, Some("xterm-256color")));
        assert!(enabled(true, None, Some("xterm-256color")));
        assert!(enabled(true, Some(""), None));
    }
    #[test]
    fn coloured_json_round_trips_unicode_escapes_nested_values_and_numbers() {
        let value = serde_json::json!({"name":"żółty ✓", "quoted":"\"key\": false", "escape":"\x1b[31m", "path":"C:\\files\\", "values":[true,false,null,-4,2.5,1.23e30,{"inner":"test"}]});
        let plain = json(&value, false);
        let rendered = json(&value, true);
        assert_eq!(without_sgr(&rendered), plain);
        assert_eq!(serde_json::from_str::<Value>(&plain).unwrap(), value);
        assert!(rendered.contains("\x1b[96m\"name\"\x1b[0m"));
        assert!(rendered.contains("\x1b[91mfalse\x1b[0m"));
        assert!(!plain.contains('\x1b'));
        for value in [serde_json::json!(null), serde_json::json!("top-level ✓"), serde_json::json!(-0.2)] {
            assert_eq!(without_sgr(&json(&value, true)), json(&value, false));
        }
    }
    #[test]
    fn help_has_a_short_start_and_keeps_every_command_available() {
        let plain = format!("Yougori — environments, models and Personal Vault\n{}\n{}", yougori_cli::public::HELP, yougori_cli::parse::HELP);
        assert_eq!(help(&plain, false), plain);
        let rendered = without_sgr(&help(&plain, true));
        assert!(rendered.starts_with("  YOUGORI\n  Environments, models and Personal Vault on this computer"));
        assert!(rendered.contains("yougori run nginx"));
        assert!(rendered.contains("PUBLIC COMMANDS"));
        assert!(rendered.contains("ADVANCED CONTROL"));
        assert!(rendered.contains("app start [--engine]|status|show|quit"));
        assert!(rendered.contains("yougori model run"));
    }
    #[test]
    fn tables_are_aligned_and_guest_text_cannot_control_the_terminal() {
        let rows = vec![vec!["web\x1b[2J\nforged".into(), "running".into()], vec!["db".into(), "stopped".into()]];
        let plain = table(&["NAME", "STATUS"], &rows, false);
        let colored = table(&["NAME", "STATUS"], &rows, true);
        assert!(!plain.contains('\x1b'));
        assert!(!plain.contains("\nforged"));
        assert!(plain.contains("web[2J forged"));
        assert!(plain.contains("────"));
        assert_eq!(without_sgr(&colored), plain);
        assert!(colored.contains("\x1b[92mrunning"));
    }
    #[test]
    fn wide_values_shorten_to_the_available_terminal_width() {
        let rows = vec![vec!["a very long environment name".into(), "running".into(), "https://example.com/this/is/a/very/long/address".into()]];
        let rendered = table_at_width(&["NAME", "STATUS", "ADDRESS"], &rows, false, Some(60));
        assert!(rendered.contains('…'));
        assert!(rendered.lines().all(|line| line.chars().count() <= 60), "{rendered}");
        assert!(rendered.contains("running"));
    }
    #[test]
    fn terminal_errors_remain_readable_and_cannot_inject_control_sequences() {
        let plain = error("Bad name\x1b[2J\nTry another", false);
        assert!(plain.contains("Bad name[2J\n   Try another"));
        assert!(!plain.contains('\x1b'));
        assert_eq!(without_sgr(&error("Bad name\x1b[2J\nTry another", true)), plain);
    }
    #[test]
    fn volume_tables_show_users_sizes_and_what_was_not_checked() {
        let listing = serde_json::json!({"volumes":[
            {"name":"data","inUse":true,"mounts":[{"environment":"db","target":"/var/lib/db"}],"stored":[{"location":"C:\\Yougori\\runtime","usedBy":["db"],"sizeBytes":1_610_612_736u64,"sizeComplete":true}]},
            {"name":"old","inUse":false,"mounts":[],"stored":[{"location":"C:\\Yougori\\runtime","usedBy":[],"sizeBytes":10,"sizeComplete":false}]},
        ],"checked":["C:\\Yougori\\runtime"],"problems":["D:\\Yougori: drive offline"],"note":"Only running container runtimes were checked."});
        let text = volumes(&listing, false);
        assert!(text.contains("data  in use  1.5 GB"), "{text}");
        assert!(text.contains("db:/var/lib/db"), "{text}");
        assert!(!text.contains("db:/var/lib/db, db"), "{text}");
        assert!(text.contains("old   unused  10 B+"), "{text}");
        assert!(text.contains("Not checked: D:\\Yougori: drive offline"));
        assert!(text.contains("Only running"));
    }
    #[test]
    fn neocloud_table_shows_rank_and_partial_provider_failures() {
        let report = serde_json::json!({
            "hours": 8, "discoveredTotal": 3, "rankedTotal": 1, "unrankedTotal": 1, "unavailableTotal": 1,
            "ranked": [{"rank":1,"provider":"vast","name":"RTX 4090","gpuCount":1,"vramGb":24,"hourlyUsd":1.125,"estimatedComputeUsd":9,"offerId":"123"}],
            "unranked": [{"provider":"jarvis"}],
            "providers": [{"provider":"runpod","status":"error","message":"not signed in"}]
        });
        let output = neocloud_prices(&report, false);
        assert!(output.contains("RTX 4090"));
        assert!(output.contains("$1.125"));
        assert!(output.contains("$9.00"));
        assert!(output.contains("runpod: error — not signed in"));
        assert!(output.contains("1 offer was marked unavailable"));
        assert!(!output.contains('\u{1b}'));
    }
}

pub fn stdout_terminal() -> bool {
    std::io::stdout().is_terminal()
}

pub fn error(message: &str, color: bool) -> String {
    let mut output = format!("{}\n", styled("Yougori could not complete the command", BAD, color));
    for line in message.lines() {
        output.push_str("   ");
        output.push_str(&safe(line));
        output.push('\n');
    }
    output
}

/// Compact columns with a quiet rule and color reserved for meaningful state.
pub fn table(headers: &[&str], rows: &[Vec<String>], color: bool) -> String {
    let width = if stdout_terminal() { crossterm::terminal::size().ok().map(|(columns, _)| columns as usize) } else { None };
    table_at_width(headers, rows, color, width)
}

fn table_at_width(headers: &[&str], rows: &[Vec<String>], color: bool, max_width: Option<usize>) -> String {
    if headers.is_empty() { return String::new(); }
    let cells: Vec<Vec<String>> = rows.iter().map(|row| row.iter().map(|cell| safe(cell)).collect()).collect();
    let mut widths: Vec<usize> = (0..headers.len())
        .map(|i| cells.iter().filter_map(|r| r.get(i)).map(|cell| cell.chars().count()).chain([headers[i].chars().count()]).max().unwrap_or(0))
        .collect();
    if let Some(max_width) = max_width.filter(|width| *width >= 60) {
        let mut excess = widths.iter().sum::<usize>() + 2 * (headers.len() - 1);
        excess = excess.saturating_sub(max_width);
        let mut flexible: Vec<usize> = (0..headers.len()).collect();
        flexible.sort_by_key(|&i| match headers[i] {
            "ID" | "OFFER ID" => 0,
            "PUBLISHED" | "ADDRESS" | "DETAIL" | "STORED IN" | "USED BY" => 1,
            "OFFER" => 2,
            "NAME" | "ENVIRONMENT" => 3,
            _ => 4,
        });
        for i in flexible {
            if excess == 0 { break; }
            let floor = headers[i].chars().count().max(if matches!(headers[i], "NAME" | "ENVIRONMENT" | "ADDRESS" | "PUBLISHED" | "DETAIL" | "OFFER" | "ID" | "OFFER ID" | "STORED IN" | "USED BY") { 12 } else { 0 });
            let cut = excess.min(widths[i].saturating_sub(floor));
            widths[i] -= cut;
            excess -= cut;
        }
    }
    let line = |values: &[String], status: bool| {
        let last = headers.len() - 1;
        (0..headers.len()).map(|i| {
            let cell = values.get(i).map(String::as_str).unwrap_or("");
            let shortened = if cell.chars().count() > widths[i] {
                format!("{}…", cell.chars().take(widths[i].saturating_sub(1)).collect::<String>())
            } else { cell.to_owned() };
            let padded = if i == last { shortened } else { format!("{shortened:<width$}", width = widths[i]) };
            if color && status && (matches!(headers[i], "STATUS" | "STATE") || headers[i].is_empty()) {
                styled(&padded, tone(cell), true)
            } else { padded }
        }).collect::<Vec<_>>().join("  ").trim_end().to_owned()
    };
    let head = line(&headers.iter().map(|h| h.to_string()).collect::<Vec<_>>(), false);
    let rule = widths.iter().enumerate().map(|(i, width)| "─".repeat(width + if i + 1 == widths.len() { 0 } else { 2 })).collect::<String>();
    let mut output = format!("{}\n{}\n", styled(&head, HEADING, color), styled(&rule, MUTED, color));
    for row in &cells {
        output.push_str(&line(row, true));
        output.push('\n');
    }
    output
}

fn text(value: &Value) -> String {
    value.as_str().map(str::to_owned).unwrap_or_else(|| if value.is_null() { "—".into() } else { value.to_string() })
}
fn percent(value: &Value) -> String { value.as_f64().map(|v| format!("{v:.0}%")).unwrap_or_else(|| "—".into()) }
fn gigabytes(value: &Value) -> String { value.as_f64().map(|v| format!("{v:.1} GB")).unwrap_or_else(|| "—".into()) }
fn links(published: &Value) -> String {
    published.as_array().into_iter().flatten().map(|p| format!(":{} {}", p["port"], p["urls"][0].as_str().unwrap_or(p["kind"].as_str().unwrap_or("")))).collect::<Vec<_>>().join(", ")
}

pub fn ps(environments: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = environments.as_array().into_iter().flatten().map(|env| vec![
        text(&env["name"]), yougori_cli::overview::env_type(env).into(), text(&env["status"]),
        percent(&env["cpuUsage"]), gigabytes(&env["memoryUsageGb"]), text(&env["id"]),
    ]).collect();
    let mut output = section("Environments", color);
    if rows.is_empty() { output.push_str("No environments yet. Start one with `yougori run IMAGE`.\n"); }
    else { output.push_str(&table(&["NAME", "TYPE", "STATUS", "CPU", "MEMORY", "ID"], &rows, color)); }
    output
}

/// Terminal views for `yougori bounty` results; none means the JSON is shown instead.
pub fn bounty(action: &str, result: &Value, color: bool) -> Option<String> {
    match action {
        "workers" => Some(bounty_workers(&result["workers"], color)),
        "status" | "memory" if result["worker"].is_object() => Some(bounty_worker(&result["worker"], color)),
        "offers" => Some(bounty_offers(&result["offers"], color)),
        "doctor" if result["worker"].is_object() => Some(bounty_doctor(result, color)),
        "practice" if result["practice"] == true || result["stopped"].is_boolean() => Some(bounty_practice(result, color)),
        _ => None,
    }
}

/// How a practice without a console ended, or what `bounty practice WORKER --stop` did.
fn bounty_practice(result: &Value, color: bool) -> String {
    let line = if result["practice"] == true {
        text(&result["message"])
    } else if result["stopped"] == true {
        "Practice stopped. Your worker is waiting for offers.".into()
    } else {
        "No practice was running.".into()
    };
    let mut output = section("Practice bounty", color);
    output.push_str(&format!("{}\n", safe(&line)));
    output.push_str(&format!("{}\n", styled(&format!("Worker: {}", safe(&text(&result["handle"]))), MUTED, color)));
    output
}

fn bounty_doctor(result: &Value, color: bool) -> String {
    let mut output = bounty_worker(&result["worker"], color);
    output.push('\n');
    output.push_str(&section("Checks", color));
    for (ok, good, attention) in [
        (result["credentialConfigured"] == true, "Registered with yougori.com", "Not registered with yougori.com yet; this finishes when preparation succeeds"),
        (result["localOnly"] != false, "Model API stays private on this computer", "Model API can be reached from outside this computer"),
        (result["publicInference"] != true, "Not shared on Neo Grid", "Also shared on Neo Grid"),
    ] {
        let (mark, text, style) = if ok { ("OK  ", good, GOOD) } else { ("WARN", attention, WARN) };
        output.push_str(&format!("{}  {text}\n", styled(mark, style, color)));
    }
    output
}

fn worker_state(worker: &Value) -> String {
    yougori_cli::bounty::state_label(worker["state"].as_str().unwrap_or("")).into()
}

fn worker_model(worker: &Value) -> String {
    text(&worker["model"]).trim_start_matches("hf.co/").to_owned()
}

/// Paused by an engine restart: nothing runs until the participant resumes it.
fn restored(worker: &Value) -> bool {
    worker["state"] == "paused" && worker["restored"] == true
}

/// The newest report draft waiting for the participant's review.
fn review_draft(worker: &Value) -> Option<String> {
    worker["reviewReports"].as_array().and_then(|drafts| drafts.last()).and_then(Value::as_str).map(safe)
}

/// The error if there is one, otherwise what the worker is doing.
fn worker_detail(worker: &Value) -> String {
    if restored(worker) {
        return "paused when the engine restarted".into();
    }
    let first = |value: &Value| value.as_str().and_then(|s| s.lines().find(|line| !line.trim().is_empty())).map(str::to_owned);
    first(&worker["error"]).or_else(|| first(&worker["stage"])).unwrap_or_else(|| match worker["state"].as_str() {
        Some("paused") => "progress saved".into(),
        Some("ready_waiting" | "waiting" | "ready") => "waiting for bounty offers".into(),
        _ => "—".into(),
    })
}

fn bounty_workers(workers: &Value, color: bool) -> String {
    let workers = workers.as_array().map(Vec::as_slice).unwrap_or_default();
    // What to type for each worker: its short name, or its ID where two listed workers share one.
    let names = yougori_cli::bounty::worker_names(&workers.iter().collect::<Vec<_>>());
    let rows: Vec<Vec<String>> = workers.iter().zip(&names).map(|(worker, handle)| vec![
        text(&worker["name"]), worker_state(worker), worker_model(worker), worker_detail(worker), handle.clone(),
    ]).collect();
    let mut output = section("Bounty workers", color);
    if rows.is_empty() {
        output.push_str("No bounty workers yet. Start one with `yougori start bounty`.\n");
        return output;
    }
    output.push_str(&table(&["NAME", "STATE", "MODEL", "DETAIL", "WORKER"], &rows, color));
    // Workers that wait for the participant get their exact next command.
    let listed = || workers.iter().zip(&names).map(|(worker, handle)| (worker, safe(&text(&worker["name"])), handle));
    let paused: Vec<_> = listed().filter(|(worker, ..)| restored(worker)).collect();
    if !paused.is_empty() {
        output.push_str(&format!("\n{}\n", styled("The engine restarted, so these workers paused. Nothing runs until you resume them:", WARN, color)));
        for (_, name, handle) in paused {
            output.push_str(&format!("Resume {name}: yougori bounty resume {handle}\n"));
        }
    }
    let drafts: Vec<_> = listed().filter(|(worker, ..)| worker["state"] == "awaiting_review")
        .filter_map(|(worker, name, handle)| review_draft(worker).map(|report| (name, handle, report))).collect();
    if !drafts.is_empty() {
        output.push_str(&format!("\n{}\n", styled("Report drafts wait for your review. Read them with yougori bounty reports WORKER, then submit:", WARN, color)));
        for (name, handle, report) in drafts {
            output.push_str(&format!("Submit {name}'s draft: yougori bounty submit {handle} {report} --yes\n"));
        }
    }
    output.push_str(&format!("\n{}\n", styled("Open one: yougori start bounty --worker WORKER", MUTED, color)));
    output
}

fn bounty_worker(worker: &Value, color: bool) -> String {
    // Commands name the worker by its memorable name, else its short name, or by its ID when
    // another worker shares that name (`handleShared`); the ID stays in the card for reference.
    let handle = yougori_cli::bounty::typed_in_result(worker);
    let state = worker_state(worker);
    let resources = &worker["resources"];
    let mut runs = vec![match worker["gpu"].as_str() {
        Some("cpu") => "Processor".to_owned(),
        Some("metal") => "Apple Metal".to_owned(),
        _ => "NVIDIA GPU".to_owned(),
    }];
    if let Some(cpu) = resources["cpu"].as_f64() { runs.push(format!("{cpu} CPU")); }
    if let Some(memory) = resources["memoryGb"].as_f64() { runs.push(format!("{memory} GB")); }
    if let Some(drive) = resources["storageDrive"].as_str() { runs.push(drive.to_owned()); }
    let drafts: Vec<&str> = worker["reviewReports"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let mut rows = vec![("Name", text(&worker["name"]))];
    // A name that is what to type is shown once.
    if handle != text(&worker["name"]) {
        rows.push(("Worker", handle.clone()));
    }
    rows.extend([
        ("State", state.clone()),
        ("Model", worker_model(worker)),
        ("Runs on", runs.join(" · ")),
        ("Workspace", worker["workspaceQuotaGb"].as_f64().map_or_else(|| "—".into(), |gb| format!("{gb} GB for bounty workspaces"))),
        ("Model memory", match worker["keepResident"].as_bool() {
            Some(true) => "kept loaded while waiting".into(),
            Some(false) => "loaded only for work".into(),
            None => "—".into(),
        }),
    ]);
    if !worker["bountyId"].is_null() { rows.push(("Bounty", text(&worker["bountyId"]))); }
    rows.push(("Attempts", text(&worker["completedAttempts"])));
    if !drafts.is_empty() {
        rows.push(("Drafts", format!("{} · waiting for your review", drafts.join(", "))));
    }
    rows.push((if worker["error"].is_string() { "Problem" } else { "Doing" }, worker_detail(worker)));
    rows.push(("ID", text(&worker["id"])));
    let mut output = section("Bounty worker", color);
    // Values line up after the longest label.
    let pad = rows.iter().map(|(label, _)| label.len()).max().unwrap_or(0);
    for (label, value) in rows {
        let value = safe(&value);
        let value = if label == "State" || label == "Problem" { styled(&value, tone(if label == "Problem" { "failed" } else { &state }), color) } else { value };
        output.push_str(&format!("{}  {value}\n", styled(&format!("{label:<pad$}"), MUTED, color)));
    }
    if restored(worker) {
        output.push_str(&format!("\n{}", styled("The engine restarted, so this worker paused. Nothing runs until you resume it.", WARN, color)));
    }
    let report = review_draft(worker).unwrap_or_else(|| "REPORT_ID".into());
    let next = match worker["state"].as_str().unwrap_or("") {
        "paused" => format!("Resume: yougori bounty resume {handle}"),
        "stopped" => format!("Start again: yougori start bounty --worker {handle}"),
        "awaiting_review" => format!("Read the draft: yougori bounty reports {handle}  ·  Submit it: yougori bounty submit {handle} {report} --yes"),
        _ if worker["error"].is_string() => format!("Check it: yougori bounty doctor {handle}  ·  Try again: yougori start bounty --worker {handle}"),
        _ => format!("Open the live view: yougori start bounty --worker {handle}"),
    };
    output.push_str(&format!("\n{}\n", styled(&next, MUTED, color)));
    output
}

fn bounty_offers(offers: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = offers.as_array().into_iter().flatten().map(|offer| {
        let reward = format!("{} {}", text(&offer["reward"]["amount"]), offer["reward"]["currency"].as_str().unwrap_or("")).trim().to_owned();
        vec![text(&offer["bounty"]["title"]), reward, offer["id"].as_str().or(offer["bounty"]["id"].as_str()).unwrap_or("—").to_owned()]
    }).collect();
    let mut output = section("Bounty offers", color);
    if rows.is_empty() {
        output.push_str("No offers right now. Your worker keeps waiting; new offers appear in its live view.\n");
        return output;
    }
    output.push_str(&table(&["BOUNTY", "REWARD", "OFFER ID"], &rows, color));
    output.push_str(&format!("\n{}\n", styled("Review one: yougori bounty details WORKER OFFER_ID, or press O in the live view", MUTED, color)));
    output
}

pub fn ports(publications: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = publications.as_array().into_iter().flatten().map(|row| {
        let p = &row["publication"];
        vec![text(&row["environment"]), text(&p["port"]), if p["domain"] == true { "domain".into() } else { text(&p["kind"]) }, text(&p["status"]), text(&p["id"]), p["urls"].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join(" ")]
    }).collect();
    let mut output = section("Published ports", color);
    if rows.is_empty() { output.push_str("Nothing is published. Publish a port with `yougori ports publish ENV --port N --kind local|cloudflare --yes`.\n"); }
    else { output.push_str(&table(&["ENVIRONMENT", "PORT", "KIND", "STATUS", "ID", "ADDRESS"], &rows, color)); }
    output
}

pub fn neocloud_prices(report: &Value, color: bool) -> String {
    let hours = report["hours"].as_f64().unwrap_or(1.0);
    let rows: Vec<Vec<String>> = report["ranked"].as_array().into_iter().flatten().map(|quote| {
        let gpu = quote["gpuCount"].as_u64().map(|n| n.to_string()).unwrap_or_else(|| "—".into());
        let vram = quote["vramGb"].as_f64().map(|n| format!("{n} GB")).unwrap_or_else(|| "—".into());
        let hourly = quote["hourlyUsd"].as_f64().map(|n| format!("${n:.3}")).unwrap_or_else(|| "—".into());
        let estimate = quote["estimatedComputeUsd"].as_f64().map(|n| format!("${n:.2}")).unwrap_or_else(|| "—".into());
        vec![text(&quote["rank"]), text(&quote["provider"]), text(&quote["name"]), gpu, vram, hourly, estimate, text(&quote["offerId"])]
    }).collect();
    let mut rendered = section("Neocloud prices", color);
    rendered.push_str(&format!("{}\n\n", styled(&format!("{} offers discovered  ·  {} ranked  ·  {hours}h estimate", report["discoveredTotal"].as_u64().unwrap_or(0), report["rankedTotal"].as_u64().unwrap_or(0)), MUTED, color)));
    rendered.push_str(&if rows.is_empty() { "No comparable hourly USD offers were returned.\n".into() }
        else { table(&["#", "PROVIDER", "OFFER", "GPUS", "VRAM/GPU", "USD/HR", "COMPUTE EST.", "OFFER ID"], &rows, color) });
    rendered.push_str(&format!("The {hours}h estimate covers compute only.\n"));
    let unranked = report["unrankedTotal"].as_u64().unwrap_or(0);
    if unranked > 0 { rendered.push_str(&format!("{unranked} offer{} lacked a comparable USD hourly quote; use --format json to inspect {}.\n", if unranked == 1 { "" } else { "s" }, if unranked == 1 { "it" } else { "them" })); }
    let unavailable = report["unavailableTotal"].as_u64().unwrap_or(0);
    if unavailable > 0 { rendered.push_str(&format!("{unavailable} offer{} {} marked unavailable by the provider; use --format json to inspect {}.\n", if unavailable == 1 { "" } else { "s" }, if unavailable == 1 { "was" } else { "were" }, if unavailable == 1 { "it" } else { "them" })); }
    for provider in report["providers"].as_array().into_iter().flatten() {
        let status = provider["status"].as_str().unwrap_or("unknown");
        if status != "ok" {
            let message = provider["message"].as_str().unwrap_or("").replace(['\r', '\n'], " ");
            rendered.push_str(&format!("{}: {} — {}\n", safe(&text(&provider["provider"])), safe(status), safe(&message)));
        }
    }
    rendered.push_str("Confirm the provider checkout price before creating; storage, network, taxes and stopped-resource charges are excluded.\n");
    rendered
}

fn bytes(value: &Value) -> String {
    let Some(v) = value.as_f64() else { return "—".into() };
    let units = ["B", "KB", "MB", "GB", "TB"];
    let exponent = if v < 1.0 { 0 } else { ((v.log(1024.0)).floor() as usize).min(units.len() - 1) };
    if exponent == 0 { format!("{v:.0} B") } else { format!("{:.1} {}", v / 1024f64.powi(exponent as i32), units[exponent]) }
}

pub fn volumes(listing: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = listing["volumes"].as_array().into_iter().flatten().map(|volume| {
        let mut users: Vec<String> = volume["mounts"].as_array().into_iter().flatten().map(|m| format!("{}:{}", text(&m["environment"]), text(&m["target"]))).collect();
        for stored in volume["stored"].as_array().into_iter().flatten() {
            for user in stored["usedBy"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                if !users.iter().any(|u| u.starts_with(&format!("{user}:"))) { users.push(user.to_owned()); }
            }
        }
        let stored = volume["stored"].as_array().cloned().unwrap_or_default();
        let size = if stored.iter().any(|s| s["sizeBytes"].is_number()) {
            let total: f64 = stored.iter().filter_map(|s| s["sizeBytes"].as_f64()).sum();
            format!("{}{}", bytes(&total.into()), if stored.iter().any(|s| s["sizeComplete"] == false) { "+" } else { "" })
        } else { "—".into() };
        vec![
            text(&volume["name"]),
            if volume["inUse"] == true { "in use".into() } else { "unused".into() },
            size,
            if stored.is_empty() { "not checked".into() } else { stored.iter().map(|s| text(&s["location"])).collect::<Vec<_>>().join(", ") },
            if users.is_empty() { "—".into() } else { users.join(", ") },
        ]
    }).collect();
    let mut output = section("Volumes", color);
    output.push_str(&if rows.is_empty() { "No volumes found.\n".to_owned() } else { table(&["NAME", "STATE", "SIZE", "STORED IN", "USED BY"], &rows, color) });
    for problem in listing["problems"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        output.push_str(&format!("Not checked: {}\n", safe(problem)));
    }
    if let Some(note) = listing["note"].as_str() {
        output.push_str(&format!("{}\n", safe(note)));
    }
    output
}

pub fn top(snapshot: &Value, color: bool) -> String {
    let host = &snapshot["host"];
    let mut output = section("Live usage", color);
    output.push_str(&format!("{}  CPU {} / {} cores    Memory {} / {}    GPU {}\n\n",
        styled("THIS PC", ACCENT, color), percent(&host["cpuPercent"]), safe(&text(&host["cpus"])), gigabytes(&host["memoryGb"]), gigabytes(&host["totalMemoryGb"]), percent(&host["gpuPercent"])));
    let rows: Vec<Vec<String>> = snapshot["environments"].as_array().into_iter().flatten().map(|env| vec![
        text(&env["name"]), text(&env["type"]), percent(&env["cpuPercent"]), gigabytes(&env["memoryGb"]),
        format!("+{}", gigabytes(&env["storageAddedGb"])), env["networkMbps"].as_f64().map(|v| format!("{v:.1} Mb/s")).unwrap_or_else(|| "—".into()),
        text(&env["blocked"]), text(&env["security"]),
    ]).collect();
    if rows.is_empty() { output.push_str("No environments are running.
"); }
    else { output.push_str(&table(&["NAME", "TYPE", "CPU", "MEMORY", "STORAGE", "NETWORK", "BLOCKED", "SECURITY"], &rows, color)); }
    output.push_str(&security_line(&snapshot["security"], color));
    output
}

/// One line about monitoring for `status` and `top`; empty for engines without it.
fn security_line(summary: &Value, color: bool) -> String {
    if !summary.is_object() {
        return String::new();
    }
    let contained = summary["contained"].as_array().map(Vec::len).unwrap_or(0);
    let alerts = summary["alerts"].as_u64().unwrap_or(0);
    let state = if summary["monitoring"] == false { styled("monitoring off", WARN, color) } else { "monitoring on".into() };
    let problems = format!("{alerts} alert{}  ·  {contained} contained", if alerts == 1 { "" } else { "s" });
    let problems = if alerts + contained as u64 > 0 { styled(&problems, WARN, color) } else { problems };
    format!("Security: {state}  ·  {problems}  ·  `yougori monitor`\n")
}

fn ratio(value: &Value) -> String {
    value.as_f64().map(|v| format!("{:.0}%", v * 100.0)).unwrap_or_else(|| "—".into())
}

fn count(value: &Value) -> String {
    value.as_u64().map(|v| v.to_string()).unwrap_or_else(|| "—".into())
}

/// The name to type in a suggested command: the name when it is one word, else the ID.
fn command_target(entry: &Value) -> String {
    let name = entry["name"].as_str().unwrap_or("");
    if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) { name.into() } else { text(&entry["id"]) }
}

/// `yougori monitor`: one row per environment, then alerts and what is not measured.
pub fn monitor(snapshot: &Value, color: bool) -> String {
    let policies = &snapshot["policies"];
    let mut output = section("Security monitor", color);
    let state = if snapshot["monitoring"] == false { styled("Monitoring off", WARN, color) } else { styled("Monitoring on", GOOD, color) };
    output.push_str(&format!("{state}  ·  kill switches: PC ports {}, metadata {}  ·  notifications {}\n\n",
        safe(&text(&policies["hostPortProbe"])), safe(&text(&policies["metadataProbe"])), if snapshot["notifications"] == false { "off" } else { "on" }));
    let mut rows = Vec::new();
    let mut notes = Vec::new();
    for env in snapshot["environments"].as_array().into_iter().flatten() {
        let network = &env["network"];
        let measured = network.is_object();
        let traffic = |value: &Value| if measured { count(value) } else { "—".into() };
        rows.push(vec![
            text(&env["name"]), text(&env["type"]), text(&env["status"]), yougori_cli::security::label(env),
            traffic(&network["blockedLast10m"]), traffic(&network["connectionsLastMinute"]),
            if measured { bytes(&network["egressLastHourBytes"]) } else { "—".into() },
            ratio(&env["cpuRatio"]), ratio(&env["memoryRatio"]),
        ]);
        let target = command_target(env);
        if let Some(containment) = env["containment"].as_object() {
            notes.push(styled(&format!("■ {}: {} since {} ({}). Review `yougori audit {target}`, then `yougori unlock {target} --yes`.",
                safe(&text(&env["name"])), safe(&text(&containment["level"])), safe(&text(&containment["since"])), safe(&text(&containment["reason"]))), BAD, color));
        }
        for alert in env["alerts"].as_array().into_iter().flatten() {
            let actions = alert["actions"].as_array().filter(|actions| !actions.is_empty())
                .map(|actions| format!(", steps: {}", actions.iter().map(text).collect::<Vec<_>>().join(", "))).unwrap_or_default();
            notes.push(styled(&format!("! {}: {} for {} min{actions}", safe(&text(&env["name"])), safe(&text(&alert["rule"])), alert["sinceSeconds"].as_u64().unwrap_or(0) / 60), WARN, color));
        }
    }
    for pool in snapshot["pools"].as_array().into_iter().flatten() {
        let summary = &pool["summary"];
        let network = &summary["network"];
        rows.push(vec![
            text(&pool["label"]), "shared VM".into(), "—".into(), yougori_cli::security::label(summary),
            count(&network["blockedLast10m"]), count(&network["connectionsLastMinute"]), bytes(&network["egressLastHourBytes"]), "—".into(), "—".into(),
        ]);
        for alert in summary["alerts"].as_array().into_iter().flatten() {
            notes.push(styled(&format!("! {}: {} (alert only: the shared VM cannot be cut off per container)", safe(&text(&pool["label"])), safe(&text(&alert["rule"]))), WARN, color));
        }
    }
    if rows.is_empty() {
        output.push_str("No environments yet.\n");
    } else {
        output.push_str(&table(&["NAME", "TYPE", "STATUS", "SECURITY", "BLOCKED 10M", "CONN/MIN", "SENT 1H", "CPU", "MEMORY"], &rows, color));
    }
    for note in notes {
        output.push_str(&note);
        output.push('\n');
    }
    output.push_str(&styled("Blocked: refused attempts to reach PC ports, link-local/metadata addresses or the Internet while it is off.\n\
— not measured for this type; container network counters and process-limit hits need a guest agent update.\n", MUTED, color));
    output
}

fn audit_detail(record: &Value) -> String {
    let mut parts = Vec::new();
    if record["outcome"] == "failed" {
        parts.push("failed".to_owned());
    }
    for (key, value) in record["detail"].as_object().into_iter().flatten() {
        if matches!(key.as_str(), "commandHash" | "removedLastHash") {
            continue;
        }
        let shown = match value {
            Value::String(text) => text.clone(),
            Value::Array(items) => items.iter().map(text).collect::<Vec<_>>().join(", "),
            Value::Object(_) => value.to_string(),
            other => other.to_string(),
        };
        parts.push(format!("{key}={shown}"));
    }
    parts.join("  ")
}

fn short_time(value: &Value) -> String {
    value.as_str().map(|time| time.replacen('T', " ", 1).trim_end_matches('Z').split('.').next().unwrap_or(time).to_owned()).unwrap_or_else(|| "—".into())
}

/// `yougori audit`: optional chain check, then records oldest first. Environments are named
/// from the platform `state`; one that no longer exists keeps its ID.
pub fn audit(result: &Value, state: &Value, color: bool) -> String {
    let mut output = String::new();
    let verification = &result["verification"];
    if verification.is_object() {
        output.push_str(&section("Audit log check", color));
        if verification["ok"] == true {
            output.push_str(&format!("{}  {} records (#{}–#{}) in {} segments, anchored at #{}\n",
                styled("Chain intact.", GOOD, color), count(&verification["records"]), count(&verification["firstSeq"]),
                count(&verification["lastSeq"]), count(&verification["segments"]), count(&verification["anchoredSeq"])));
        } else {
            output.push_str(&format!("{}\n", styled("Chain broken: the log was changed, reordered or truncated outside Yougori.", BAD, color)));
            for problem in verification["problems"].as_array().into_iter().flatten().take(10) {
                let place = problem["seq"].as_u64().map(|seq| format!("record #{seq}: ")).unwrap_or_default();
                output.push_str(&format!("  {place}{}\n", safe(&text(&problem["problem"]))));
            }
        }
        for incident in verification["incidents"].as_array().into_iter().flatten() {
            output.push_str(&styled(&format!("Incident at record #{}, {}: {}\n", count(&incident["seq"]), safe(&text(&incident["event"])), safe(&incident["detail"].to_string())), WARN, color));
        }
        for warning in verification["warnings"].as_array().into_iter().flatten() {
            output.push_str(&styled(&format!("  note: {}\n", safe(&text(&warning["warning"]))), MUTED, color));
        }
        output.push('\n');
    }
    output.push_str(&section("Audit log", color));
    let rows: Vec<Vec<String>> = result["records"].as_array().into_iter().flatten().map(|record| vec![
        short_time(&record["time"]), if record["env"].is_string() { environment_name(state, &record["env"]) } else { "—".into() },
        text(&record["event"]), text(&record["via"]), audit_detail(record),
    ]).collect();
    if rows.is_empty() {
        output.push_str("No matching records.\n");
    } else {
        output.push_str(&table(&["TIME (UTC)", "ENVIRONMENT", "EVENT", "BY", "DETAIL"], &rows, color));
    }
    output.push_str(&styled(&format!("{} records shown · stored in {}\n", count(&result["count"]), safe(&text(&result["folder"]))), MUTED, color));
    output
}

/// `yougori lockdown` / `unlock`: what happened to each environment and how to undo it.
pub fn containment(result: &Value, unlock: bool, color: bool) -> String {
    let mut output = section(if unlock { "Unlock" } else { "Lockdown" }, color);
    let mut released = false;
    for env in result["environments"].as_array().into_iter().flatten() {
        let name = env["name"].as_str().map(str::to_owned).unwrap_or_else(|| text(&env["id"]));
        let line = if let Some(reason) = env["skipped"].as_str() {
            styled(&format!("{}: skipped ({})", safe(&name), safe(reason)), MUTED, color)
        } else if let Some(error) = env["error"].as_str() {
            styled(&format!("{}: failed, {}", safe(&name), safe(error)), BAD, color)
        } else if unlock && env["unlocked"] == false {
            styled(&format!("{}: was not locked down", safe(&name)), MUTED, color)
        } else {
            released |= unlock;
            let steps: Vec<String> = env["steps"].as_array().into_iter().flatten().map(|step| {
                let what = match step["step"].as_str().unwrap_or("") {
                    "cutInternet" => "Internet cut",
                    "pause" => "paused",
                    "restoreInternet" => "Internet restored",
                    "resume" => "resumed",
                    other => other,
                };
                if step["ok"] == true { what.to_owned() } else { format!("could not complete \"{what}\": {}", text(&step["error"])) }
            }).collect();
            let summary = if steps.is_empty() { if unlock { "unlocked; nothing to restore".to_owned() } else { "already contained".to_owned() } } else { steps.join(", ") };
            let ok = env["ok"] != false;
            styled(&format!("{}: {}{}", safe(&name), safe(&summary), if ok { "" } else { " (failed)" }), if ok { GOOD } else { BAD }, color)
        };
        output.push_str(&line);
        output.push('\n');
    }
    let note = if unlock {
        if released { "Automatic kill switches for these environments wait 30 minutes; alerts continue." } else { "" }
    } else if result["all"] == true {
        "Review with `yougori audit`, then undo with `yougori unlock --all --yes`."
    } else {
        "Review with `yougori audit ENV`, then undo with `yougori unlock ENV --yes`."
    };
    if !note.is_empty() {
        output.push_str(&styled(note, MUTED, color));
        output.push('\n');
    }
    output
}

pub fn doctor(report: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = report["checks"].as_array().into_iter().flatten().map(|c| {
        let status = match c["status"].as_str() { Some("ok") => "OK", Some("warning") => "WARN", Some("error") => "FAIL", _ => "INFO" };
        let detail = match c["fix"].as_str() { Some(fix) => format!("{}. Fix: {fix}", text(&c["detail"]).trim_end_matches('.')), None => text(&c["detail"]) };
        vec![status.into(), text(&c["name"]), detail]
    }).collect();
    let verdict = if report["ready"] == true { "Ready" } else { "Needs attention — fix the FAIL checks first" };
    let verdict_color = if report["ready"] == true { GOOD } else { BAD };
    format!("{}{}\n{}\n", section("System check", color), table(&["", "CHECK", "DETAIL"], &rows, color), styled(verdict, verdict_color, color))
}

pub fn status(overview: &Value, color: bool) -> String {
    if overview["engine"]["running"] != true {
        return format!("{}{}\n{}\n", section("Yougori status", color), styled("The Yougori engine is not running.", BAD, color), safe(&text(&overview["hint"])));
    }
    let envs = &overview["environments"];
    let types = envs["byType"].as_object().map(|t| t.iter().map(|(k, v)| format!("{v} {k}")).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    let sharing = &overview["sharing"];
    let domains = overview["savedDomains"].as_array().map(|d| d.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).filter(|d| !d.is_empty()).unwrap_or_else(|| "none".into());
    let mut output = format!(
        "{}{}  version {}\n{} environments  ·  {} running  ·  {} connections  ·  {} active jobs\n",
        section("Yougori status", color), styled("Engine running", GOOD, color), safe(&text(&overview["engine"]["version"])), envs["total"], envs["running"], overview["connections"], overview["activeJobs"],
    );
    if !types.is_empty() { output.push_str(&format!("{}\n", styled(&safe(&types), MUTED, color))); }
    output.push_str(&format!("Sharing: {}  ·  Saved domains: {}\n",
        if sharing["link"].is_string() { format!("link on, {} people", sharing["people"]) } else { "link off".into() }, safe(&domains)));
    output.push_str(&security_line(&overview["security"], color));
    output.push('\n');
    let rows: Vec<Vec<String>> = envs["list"].as_array().into_iter().flatten().map(|env| vec![
        text(&env["name"]), text(&env["type"]), text(&env["status"]), percent(&env["cpuPercent"]), gigabytes(&env["memoryGb"]), text(&env["security"]), links(&env["published"]),
    ]).collect();
    if rows.is_empty() {
        output.push_str("No environments yet. Create one with `yougori run IMAGE`.\n");
    } else {
        output.push_str(&section("Environments", color));
        output.push_str(&table(&["NAME", "TYPE", "STATUS", "CPU", "MEMORY", "SECURITY", "PUBLISHED"], &rows, color));
    }
    output
}

// ---- Views: read-only results as text at a terminal. `--format json` keeps the JSON. ----

/// One record as labelled lines; a field without a value is left out.
fn fields(rows: &[(&str, String)], color: bool) -> String {
    let width = rows.iter().filter(|(_, value)| !value.is_empty()).map(|(label, _)| label.chars().count()).max().unwrap_or(0);
    rows.iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(label, value)| format!("{}  {}\n", styled(&format!("{label:<width$}"), MUTED, color), safe(value)))
        .collect()
}
/// `2026-10-19T23:01:57.18Z` as `2026-10-19 23:01`.
fn when(value: &Value) -> String {
    value.as_str().filter(|s| s.len() >= 16).map(|s| s[..16].replace('T', " ")).unwrap_or_else(|| "—".into())
}
/// An environment's name from the platform state, or its ID when the state does not have it.
fn environment_name(state: &Value, id: &Value) -> String {
    state["environments"].as_array().into_iter().flatten()
        .find(|env| env["id"] == *id)
        .and_then(|env| env["name"].as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| text(id))
}
fn on_off(value: &Value) -> String {
    if value == true { "on".into() } else { "off".into() }
}

/// `yougori inspect ENV` and `env show`.
pub fn details(env: &Value, color: bool) -> String {
    let policy = &env["resourcePolicy"];
    let range = |key: &str, unit: &str| {
        let (min, max) = (policy[key]["min"].as_f64(), policy[key]["max"].as_f64());
        match (min, max) {
            (Some(min), Some(max)) if (min - max).abs() < f64::EPSILON => format!("{min} {unit}"),
            (Some(min), Some(max)) => format!("{min} to {max} {unit}"),
            _ => String::new(),
        }
    };
    let used = |value: &Value, unit: &str| value.as_f64().filter(|v| *v > 0.0).map(|v| format!("  ·  using {v:.1} {unit}")).unwrap_or_default();
    let mut output = section(env["name"].as_str().unwrap_or("Environment"), color);
    output.push_str(&fields(&[
        ("Status", text(&env["status"])),
        ("Type", yougori_cli::overview::env_type(env).into()),
        ("Runs", env["runtime"].as_str().unwrap_or("").into()),
        ("CPU", format!("{}{}", range("cpu", "cores"), env["cpuUsage"].as_f64().filter(|v| *v > 0.0).map(|v| format!("  ·  using {v:.0}%")).unwrap_or_default())),
        ("Memory", format!("{}{}", range("memoryGb", "GB"), used(&env["memoryUsageGb"], "GB"))),
        ("Storage", env["storageLimitGb"].as_f64().map(|limit| format!("{limit} GB limit{}", used(&env["storageDeltaGb"], "GB"))).unwrap_or_default()),
        ("Internet", on_off(&env["networkAccess"])),
        ("GPU", on_off(&env["gpuAccess"])),
        ("Command", env["containerCommand"].as_str().unwrap_or("").into()),
        ("About", env["description"].as_str().unwrap_or("").into()),
        ("Created", if env["createdAt"].as_str().is_some_and(|s| !s.is_empty()) { when(&env["createdAt"]) } else { String::new() }),
        ("Last error", env["lastError"].as_str().unwrap_or("").into()),
        ("ID", text(&env["id"])),
    ], color));
    output
}

/// `yougori logs ENV` without --follow: the output itself, and a next step when there is none.
pub fn logs(window: &Value, name: &str, color: bool) -> String {
    let text = window["logs"].as_str().or(window["stdout"].as_str()).unwrap_or("");
    if text.trim().is_empty() {
        return format!("No output from {} yet. Follow it live with yougori logs {} --follow.\n", safe(name), safe(name));
    }
    let mut output = text.to_owned();
    if !output.ends_with('\n') {
        output.push('\n');
    }
    if window["truncated"] == true {
        let next = match window["nextCursor"].as_str() {
            Some(cursor) => format!("Newer output did not fit. Read on with yougori logs {} --cursor {}, or show more at once with --limit (up to 65536).", safe(name), safe(cursor)),
            None => format!("Newer output did not fit. Show more at once with yougori logs {} --limit 65536.", safe(name)),
        };
        output.push_str(&styled(&next, MUTED, color));
        output.push('\n');
    }
    output
}

/// `yougori ports list ENV`: what listens in the environment and what is published.
pub fn services(listing: &Value, name: &str, color: bool) -> String {
    let listening: Vec<Vec<String>> = listing["services"].as_array().into_iter().flatten().map(|service| vec![
        text(&service["port"]),
        service["name"].as_str().filter(|n| !n.is_empty()).unwrap_or("—").into(),
        service["protocol"].as_str().unwrap_or("tcp").into(),
    ]).collect();
    let published: Vec<Vec<String>> = listing["publications"].as_array().into_iter().flatten().map(|p| vec![
        text(&p["port"]),
        text(&p["kind"]),
        text(&p["status"]),
        p["urls"].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join(" "),
    ]).collect();
    let mut output = section("Listening", color);
    output.push_str(&if listening.is_empty() { "Nothing is listening yet.\n".to_owned() } else { table(&["PORT", "NAME", "PROTOCOL"], &listening, color) });
    output.push('\n');
    output.push_str(&section("Published", color));
    output.push_str(&if published.is_empty() {
        format!("Nothing is published. Publish a port with yougori ports publish {} --port N --kind local|cloudflare --yes.\n", safe(name))
    } else {
        table(&["PORT", "KIND", "STATUS", "ADDRESS"], &published, color)
    });
    if let Some(notice) = listing["notice"].as_str().filter(|n| !n.is_empty()) {
        output.push_str(&format!("{}\n", styled(&safe(notice), MUTED, color)));
    }
    output
}

/// `yougori share list ENV`: PC folders the environment can reach.
pub fn shares(shares: &Value, name: &str, color: bool) -> String {
    let rows: Vec<Vec<String>> = shares.as_array().into_iter().flatten().map(|share| vec![
        text(&share["path"]),
        share["mountPath"].as_str().unwrap_or("—").into(),
        if share["readOnly"] == true { "view only".into() } else { "view and edit".into() },
        text(&share["id"]),
    ]).collect();
    let mut output = section("Shared PC folders", color);
    output.push_str(&if rows.is_empty() {
        format!("No PC folders are shared with {}. Share one with yougori share add {} --path PC_FOLDER --yes.\n", safe(name), safe(name))
    } else {
        table(&["PC FOLDER", "IN THE ENVIRONMENT", "ACCESS", "ID"], &rows, color)
    });
    output
}

/// `yougori snapshot list`.
pub fn snapshots(snapshots: &Value, state: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = snapshots.as_array().into_iter().flatten().map(|snapshot| vec![
        text(&snapshot["name"]),
        environment_name(state, &snapshot["environmentId"]),
        when(&snapshot["createdAt"]),
        gigabytes(&snapshot["sizeGb"]),
        text(&snapshot["status"]),
        text(&snapshot["id"]),
    ]).collect();
    let mut output = section("Snapshots", color);
    output.push_str(&if rows.is_empty() {
        "No snapshots yet. Make one with yougori snapshot create ENV --name NAME --yes.\n".to_owned()
    } else {
        table(&["NAME", "ENVIRONMENT", "TAKEN", "SIZE", "STATUS", "ID"], &rows, color)
    });
    output
}

/// `yougori backup list`: cloud backup runs.
pub fn backups(runs: &Value, state: &Value, color: bool) -> String {
    let destination = |id: &Value| state["destinations"].as_array().into_iter().flatten()
        .find(|d| d["id"] == *id).and_then(|d| d["name"].as_str()).map(str::to_owned).unwrap_or_else(|| text(id));
    let rows: Vec<Vec<String>> = runs.as_array().into_iter().flatten().map(|run| vec![
        environment_name(state, &run["environmentId"]),
        destination(&run["destinationId"]),
        when(&run["createdAt"]),
        gigabytes(&run["transferredGb"]),
        text(&run["status"]),
        text(&run["id"]),
    ]).collect();
    let mut output = section("Cloud backups", color);
    output.push_str(&if rows.is_empty() {
        "No cloud backups yet. Run one with yougori backup run ENV --destination-id ID --yes (destinations: yougori backup destinations).\n".to_owned()
    } else {
        table(&["ENVIRONMENT", "DESTINATION", "STARTED", "SENT", "STATUS", "ID"], &rows, color)
    });
    output
}

/// `yougori backup destinations`.
pub fn destinations(destinations: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = destinations.as_array().into_iter().flatten().map(|d| vec![
        text(&d["name"]),
        text(&d["provider"]),
        text(&d["location"]),
        if d["connected"] == true { "connected".into() } else { "not connected".into() },
        text(&d["id"]),
    ]).collect();
    let mut output = section("Backup destinations", color);
    output.push_str(&if rows.is_empty() {
        "No backup destinations yet. Add one with yougori backup add-destination --file destination.json --yes.\n".to_owned()
    } else {
        table(&["NAME", "PROVIDER", "LOCATION", "STATE", "ID"], &rows, color)
    });
    output
}

/// `yougori connection list`.
pub fn connections(connections: &Value, state: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = connections.as_array().into_iter().flatten().map(|c| vec![
        environment_name(state, &c["sourceId"]),
        environment_name(state, &c["targetId"]),
        c["ports"].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join(", "),
        if c["active"] == true { "active".into() } else { "off".into() },
        text(&c["id"]),
    ]).collect();
    let mut output = section("Connections", color);
    output.push_str(&if rows.is_empty() {
        "No connections yet. Let one environment reach another with yougori connection create --source SOURCE_ID --target TARGET_ID (IDs from yougori ps).\n".to_owned()
    } else {
        table(&["FROM", "TO", "PORTS", "STATE", "ID"], &rows, color)
    });
    output
}

/// `yougori gpu status`.
pub fn gpu(status: &Value, color: bool) -> String {
    let state = if status["supported"] != true { "not supported on this computer" }
        else if status["running"] == true { "running" }
        else if status["installed"] == true { "installed, not running" }
        else { "not installed" };
    let mut output = section("NVIDIA GPU runtime", color);
    output.push_str(&fields(&[
        ("State", state.into()),
        ("Update", if status["updateAvailable"] == true { "available: yougori gpu setup --yes".into() } else { String::new() }),
        ("Detail", status["detail"].as_str().unwrap_or("").into()),
    ], color));
    let checks: Vec<Vec<String>> = status["checks"].as_array().into_iter().flatten().map(|check| vec![
        text(&check["name"]),
        if check["passed"] == true { "passed".into() } else { "failed".into() },
        check["detail"].as_str().unwrap_or("").into(),
    ]).collect();
    if !checks.is_empty() {
        output.push('\n');
        output.push_str(&table(&["CHECK", "RESULT", "DETAIL"], &checks, color));
    }
    if status["supported"] == true && status["installed"] != true {
        output.push_str("Install it with yougori gpu setup --yes.\n");
    }
    output
}

/// `yougori jobs list`.
pub fn jobs(jobs: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = jobs.as_array().into_iter().flatten().map(|job| vec![
        yougori_cli::client::job_label(job["method"].as_str().unwrap_or("")).into(),
        text(&job["status"]),
        when(&job["createdAt"]),
        text(&job["jobId"]),
    ]).collect();
    let mut output = section("Jobs", color);
    output.push_str(&if rows.is_empty() { "No recent jobs.\n".to_owned() } else { table(&["WORK", "STATUS", "STARTED", "ID"], &rows, color) });
    output
}

/// `yougori images`.
pub fn images(images: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = images.as_array().into_iter().flatten().map(|image| {
        let repository = image["Repository"].as_str().unwrap_or("<none>");
        let tag = image["Tag"].as_str().filter(|t| !t.is_empty() && *t != "<none>");
        vec![
            tag.map(|t| format!("{repository}:{t}")).unwrap_or_else(|| repository.to_owned()),
            image["Size"].as_str().unwrap_or("—").into(),
            image["CreatedSince"].as_str().unwrap_or("—").into(),
        ]
    }).collect();
    let mut output = section("Images", color);
    output.push_str(&if rows.is_empty() { "No images yet. Pull one with yougori pull IMAGE.\n".to_owned() } else { table(&["IMAGE", "SIZE", "CREATED"], &rows, color) });
    output
}

/// `yougori neocloud list`: rented pods, in NeoCloud's own words for their state.
pub fn neocloud_pods(deployments: &Value, state: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = deployments.as_object().into_iter().flatten().map(|(id, pod)| {
        let running = pod["state"].as_str().is_some_and(|s| s.eq_ignore_ascii_case("running"));
        // A stopped pod still keeps its disk at the provider, so it is never shown as costing nothing.
        let hourly = pod["extra"]["hourlyUsd"].as_f64().filter(|_| running).map(|usd| format!("${usd:.2} per hour")).unwrap_or_else(|| "—".into());
        let name = pod["name"].as_str().map(str::to_owned).unwrap_or_else(|| environment_name(state, &Value::String(id.clone())));
        vec![name, text(&pod["provider"]), text(&pod["state"]), hourly, pod["location"].as_str().unwrap_or("—").into(), id.clone()]
    }).collect();
    let mut output = section("Neocloud pods", color);
    output.push_str(&if rows.is_empty() {
        "No Neocloud pods yet. Rent one in Yougori under Sandboxes, New environment, Neocloud, or with yougori neocloud create --file request.json --yes.\n".to_owned()
    } else {
        table(&["NAME", "PROVIDER", "STATE", "COST", "LOCATION", "ID"], &rows, color)
    });
    output
}

/// `yougori model status ENV`.
pub fn model_status(status: &Value, color: bool) -> String {
    let state = status["status"].as_str().unwrap_or("unknown").replace('_', " ");
    let download = &status["download"];
    let progress = match (download["receivedBytes"].as_f64(), download["totalBytes"].as_f64()) {
        (Some(done), Some(total)) if total > 0.0 => format!("{:.0}% ({} of {})", done / total * 100.0, bytes(&done.into()), bytes(&total.into())),
        _ => String::new(),
    };
    let mut output = section(status["model"].as_str().unwrap_or("Model"), color);
    output.push_str(&fields(&[
        ("State", state),
        ("Download", progress),
        ("GPU", status["gpu"].as_str().unwrap_or("").into()),
        ("Context", status["context"].as_u64().map(|n| format!("{n} tokens")).unwrap_or_default()),
        ("Precision", status["precision"].as_str().unwrap_or("").into()),
        ("Error", status["error"].as_str().unwrap_or("").into()),
    ], color));
    output
}

/// `yougori model access ENV`: the API addresses and key.
pub fn model_access(access: &Value, color: bool) -> String {
    let mut output = section(access["model"].as_str().unwrap_or("Model API"), color);
    output.push_str(&fields(&[
        ("This computer", access["apiUrl"].as_str().unwrap_or("off").into()),
        ("Public", access["publicUrl"].as_str().unwrap_or("off").into()),
        ("API key", access["apiKey"].as_str().unwrap_or("").into()),
    ], color));
    output.push_str(&styled("Keep the API key private; anyone with it can use this model.", MUTED, color));
    output.push('\n');
    output
}

/// `yougori model usage ENV`.
pub fn model_usage(usage: &Value, color: bool) -> String {
    let totals = &usage["totals"];
    let number = |value: &Value| value.as_u64().map(|n| n.to_string()).unwrap_or_else(|| "0".into());
    let mut output = section("Model usage", color);
    output.push_str(&fields(&[
        ("Requests", number(&totals["requests"])),
        ("Prompt tokens", number(&totals["prompt_tokens"])),
        ("Reply tokens", number(&totals["completion_tokens"])),
        ("Errors", number(&totals["errors"])),
        ("Refused", number(&totals["rejected"])),
    ], color));
    output
}

/// `yougori remote list`: folders and sandboxes shared through the tunnel.
pub fn remote_shares(listing: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = listing["grants"].as_array().into_iter().flatten().map(|grant| vec![
        text(&grant["username"]),
        text(&grant["permission"]),
        grant["folder"].as_str().unwrap_or("—").into(),
        text(&grant["status"]),
        if grant["expiresAt"].is_null() { "never".into() } else { when(&grant["expiresAt"]) },
        text(&grant["id"]),
    ]).collect();
    let mut output = section("Remote shares", color);
    output.push_str(&if rows.is_empty() {
        "Nothing is shared. Share with yougori remote create --file share.json --yes.\n".to_owned()
    } else {
        table(&["PERSON", "ACCESS", "FOLDER", "STATUS", "EXPIRES", "ID"], &rows, color)
    });
    output
}

/// `yougori domain list`: saved Cloudflare domains.
pub fn domains(domains: &Value, color: bool) -> String {
    let rows: Vec<Vec<String>> = domains.as_array().into_iter().flatten().map(|domain| vec![
        text(&domain["hostname"]),
        text(&domain["port"]),
        text(&domain["hostPort"]),
        text(&domain["id"]),
    ]).collect();
    let mut output = section("Saved domains", color);
    output.push_str(&if rows.is_empty() {
        "No saved domains yet. Add one with yougori domain add HOSTNAME --tunnel-port PORT --file - --yes, giving {\"token\":\"…\"} on stdin; never put the token in the command itself.\n".to_owned()
    } else {
        table(&["HOSTNAME", "APP PORT", "TUNNEL PORT", "ID"], &rows, color)
    });
    output
}

/// `yougori ls ENV [PATH]`.
pub fn folder(listing: &Value, name: &str, color: bool) -> String {
    let rows: Vec<Vec<String>> = listing["entries"].as_array().into_iter().flatten().map(|entry| vec![
        format!("{}{}", text(&entry["name"]), if entry["directory"] == true { "/" } else { "" }),
        if entry["directory"] == true { "folder".into() } else { entry.get("size").map(bytes).unwrap_or_else(|| "file".into()) },
    ]).collect();
    let mut output = section(&format!("{}  {}", name, listing["path"].as_str().unwrap_or("")), color);
    output.push_str(&if rows.is_empty() { "This folder is empty.\n".to_owned() } else { table(&["NAME", "SIZE"], &rows, color) });
    output
}

#[cfg(test)]
mod bounty_views {
    use super::*;
    use serde_json::json;

    fn handle(id: &str) -> String {
        yougori_cli::bounty::worker_handle(id)
    }

    #[test]
    fn workers_status_and_offers_read_like_sentences() {
        let workers = json!({"workers":[
            {"id":"worker-1","name":"ToA","state":"ready_waiting","model":"hf.co/owner/model","error":null,"stage":null},
            {"id":"worker-2","name":"TOOT","state":"failed","model":"owner/model","error":"copy container backing image: missing\nsecond line","stage":"Worker needs attention"}]});
        let view = bounty("workers", &workers, false).unwrap();
        assert!(view.contains("BOUNTY WORKERS") && view.contains("NAME") && view.contains("STATE") && view.contains("WORKER"), "{view}");
        assert!(view.contains("live") && view.contains("waiting for bounty offers") && view.contains("owner/model"), "{view}");
        assert!(view.contains("needs attention") && view.contains("copy container backing image") && !view.contains("second line"), "{view}");
        assert!(!view.contains("hf.co/") && !view.contains('\u{1b}'), "{view}");
        assert!(view.contains(&handle("worker-1")) && view.contains(&handle("worker-2")) && !view.contains("worker-1"), "short names replace IDs: {view}");
        assert!(view.contains("yougori start bounty --worker WORKER"), "{view}");
        assert!(bounty("workers", &json!({"workers":[]}), false).unwrap().contains("yougori start bounty"));
        let status = json!({"worker":{"id":"worker-2","name":"TOOT\u{1b}[31m","state":"failed","model":"owner/model","gpu":"nvidia",
            "resources":{"cpu":4,"memoryGb":8,"storageDrive":"D:\\"},"workspaceQuotaGb":20.0,"completedAttempts":0,"error":"backing image missing"}});
        let card = bounty("status", &status, false).unwrap();
        assert!(card.contains("NVIDIA GPU · 4 CPU · 8 GB · D:\\") && card.contains("20 GB for bounty workspaces"), "{card}");
        assert!(card.contains("Problem") && card.contains("backing image missing"), "{card}");
        let value = |label: &str| card.lines().find_map(|line| line.strip_prefix(label).filter(|rest| rest.starts_with("  ")).map(str::trim));
        assert_eq!((value("Worker"), value("ID")), (Some(handle("worker-2").as_str()), Some("worker-2")), "{card}");
        // Every value starts in one column, after the longest label ("Model memory").
        let rows: Vec<&str> = card.lines().skip(1).take_while(|line| !line.is_empty()).collect();
        let start = |line: &str| line.find("  ").map(|at| line.len() - line[at..].trim_start().len());
        assert!(rows.len() >= 8 && rows.iter().all(|line| start(line) == Some("Model memory".len() + 2)), "{card}");
        assert!(card.contains(&format!("yougori bounty doctor {0}  ·  Try again: yougori start bounty --worker {0}", handle("worker-2"))), "{card}");
        assert!(!card.contains("doctor worker-2") && !card.contains('\u{1b}'), "{card}");
        assert!(!card.contains("Bounty   "), "no empty bounty row: {card}");
        let mut metal = status.clone();
        metal["worker"]["gpu"] = json!("metal");
        assert!(bounty("status", &metal, false).unwrap().contains("Apple Metal · 4 CPU"), "a Mac worker does not claim an NVIDIA GPU");
        let offers = json!({"offers":[{"id":"offer-1","bounty":{"id":"b1","title":"Audit login"},"reward":{"amount":"250","currency":"USDC"}}]});
        let list = bounty("offers", &offers, false).unwrap();
        assert!(list.contains("Audit login") && list.contains("250 USDC") && list.contains("offer-1"), "{list}");
        assert!(bounty("offers", &json!({"offers":[]}), false).unwrap().contains("No offers right now"));
        assert!(bounty("rewards", &json!({}), false).is_none(), "other results stay JSON");
        let doctor = bounty("doctor", &json!({"worker":status["worker"],"credentialConfigured":false,"localOnly":true,"publicInference":false}), false).unwrap();
        assert!(doctor.contains("CHECKS") && doctor.contains("WARN  Not registered with yougori.com yet") && doctor.contains("OK    Model API stays private"), "{doctor}");
        assert!(bounty("doctor", &json!({"host":{}}), false).is_none(), "machine checks without a worker stay JSON");
    }

    #[test]
    fn restarted_workers_and_review_drafts_show_their_next_command() {
        let workers = json!({"workers":[
            {"id":"worker-1","name":"ToA","state":"paused","restored":true,"model":"owner/model","stage":"Paused when the Yougori engine restarted. Resume to recheck authorization and continue."},
            {"id":"worker-2","name":"Kit","state":"awaiting_review","reviewReports":["report_9"],"model":"owner/model","stage":"Your agent is reviewing the approved project"},
            {"id":"worker-3","name":"Old","state":"paused","model":"owner/model","stage":"Progress saved"}]});
        let (one, two, three) = (handle("worker-1"), handle("worker-2"), handle("worker-3"));
        let view = bounty("workers", &workers, false).unwrap();
        assert!(view.contains("paused when the engine restarted") && view.contains("Nothing runs until you resume them"), "{view}");
        assert!(view.contains(&format!("Resume ToA: yougori bounty resume {one}")) && !view.contains(&format!("bounty resume {three}")), "{view}");
        assert!(view.contains("report ready") && view.contains(&format!("Submit Kit's draft: yougori bounty submit {two} report_9 --yes")), "{view}");
        let card = bounty("status", &json!({"worker":workers["workers"][0]}), false).unwrap();
        assert!(card.contains("The engine restarted, so this worker paused") && card.contains(&format!("Resume: yougori bounty resume {one}")), "{card}");
        let card = bounty("status", &json!({"worker":workers["workers"][1]}), false).unwrap();
        assert!(card.contains("Drafts") && card.contains("report_9 · waiting for your review"), "{card}");
        assert!(card.contains(&format!("yougori bounty reports {two}")) && card.contains(&format!("yougori bounty submit {two} report_9 --yes")), "{card}");
        let card = bounty("status", &json!({"worker":workers["workers"][2]}), false).unwrap();
        assert!(!card.contains("engine restarted") && card.contains(&format!("Resume: yougori bounty resume {three}")), "{card}");
    }

    #[test]
    fn workers_that_share_a_short_name_are_listed_by_id() {
        let mut seen = std::collections::BTreeMap::new();
        let (first, second) = (0..100_000)
            .map(|n| format!("worker-{n:032x}"))
            .find_map(|id| seen.insert(handle(&id), id.clone()).map(|earlier| (earlier, id)))
            .unwrap();
        let workers = json!({"workers":[
            {"id":first,"name":"One","state":"paused","restored":true},
            {"id":second,"name":"Two","state":"ready_waiting"},
            {"id":"worker-3","name":"Three","state":"ready_waiting"}]});
        let view = bounty("workers", &workers, false).unwrap();
        assert!(view.contains(&first) && view.contains(&second) && view.contains(&handle("worker-3")), "{view}");
        assert!(view.contains(&format!("Resume One: yougori bounty resume {first}")), "{view}");
        // A status card's commands do the same once the result marks the shared name.
        let shared = json!({"worker":{"id":first,"name":"One","state":"paused","handle":handle(&first),"handleShared":true}});
        let card = bounty("status", &shared, false).unwrap();
        assert!(card.contains(&format!("Resume: yougori bounty resume {first}")) && !card.contains(&format!("resume {}", handle(&first))), "{card}");
        let alone = json!({"worker":{"id":"worker-3","name":"Three","state":"stopped"}});
        assert!(bounty("status", &alone, false).unwrap().contains(&format!("yougori start bounty --worker {}", handle("worker-3"))));
    }

    #[test]
    fn a_practice_without_a_console_and_its_stop_read_as_sentences() {
        let done = json!({"practice":true,"status":"gave_up","reportQualifies":false,"attempts":[],"handle":"apt-whale",
            "message":"No report qualified after 5 attempts, so the practice was stopped.\u{1b}[2J"});
        let view = bounty("practice", &done, false).unwrap();
        assert!(view.contains("PRACTICE BOUNTY") && view.contains("No report qualified after 5 attempts") && view.contains("Worker: apt-whale"), "{view}");
        assert!(!view.contains('\u{1b}'), "{view}");
        let stopped = bounty("practice", &json!({"stopped":true,"workerId":"worker-1","handle":"happy-turtle"}), false).unwrap();
        assert!(stopped.contains("Practice stopped") && stopped.contains("Worker: happy-turtle"), "{stopped}");
        let idle = bounty("practice", &json!({"stopped":false,"workerId":"worker-1","handle":"happy-turtle"}), false).unwrap();
        assert!(idle.contains("No practice was running"), "{idle}");
        assert!(bounty("practice", &json!({"cancelled":true}), false).is_none());
    }
}

#[cfg(test)]
mod security_views {
    use super::*;
    use serde_json::json;

    #[test]
    fn monitor_shows_measured_rows_containment_and_what_is_not_measured() {
        let snapshot = json!({"monitoring": true, "notifications": true, "policies": {"hostPortProbe": "cutInternet", "metadataProbe": "alert"},
            "environments": [
                {"id": "env-1", "name": "codex\u{1b}[31m", "type": "microvm", "status": "running", "cpuRatio": 0.5, "memoryRatio": null,
                 "network": {"blockedLast10m": 31, "connectionsLastMinute": 4, "egressLastHourBytes": 2048},
                 "alerts": [{"rule": "hostPortProbe", "sinceSeconds": 120, "actions": ["cutInternet"]}],
                 "containment": {"level": "internetCut", "since": "2026-10-11T12:00:00Z", "reason": "31 blocked PC ports tried in 60 s"}},
                {"id": "env-2", "name": "web", "type": "container", "status": "running", "cpuRatio": 0.1, "memoryRatio": 0.2, "network": null, "alerts": []}],
            "pools": [{"label": "standard containers (shared VM, D:/data)", "summary": {"network": {"blockedLast10m": 0}, "alerts": []}}]});
        let view = monitor(&snapshot, false);
        assert!(view.contains("SECURITY MONITOR") && view.contains("Monitoring on") && view.contains("PC ports cutInternet"), "{view}");
        assert!(view.contains("internet cut") && view.contains("31") && view.contains("2.0 KB") && view.contains("50%"), "{view}");
        assert!(view.contains("yougori unlock env-1 --yes"), "a name that is not one word is replaced by the ID: {view}");
        assert!(view.contains("hostPortProbe for 2 min, steps: cutInternet"), "{view}");
        assert!(view.contains("standard containers (shared VM") && view.contains("not measured"), "{view}");
        assert!(!view.contains('\u{1b}'), "guest-chosen names cannot inject escape sequences: {view}");
    }

    #[test]
    fn audit_reports_the_chain_check_and_compact_records() {
        let result = json!({"count": 2, "folder": "C:/Yougori/security/audit", "verification": {"ok": false, "records": 2,
            "problems": [{"seq": 7, "problem": "record was changed after it was written (hash mismatch)"}],
            "incidents": [{"seq": 9, "event": "audit.truncated", "detail": {"anchoredSeq": 12, "lastSeq": 8}}], "warnings": []},
            "records": [
                {"seq": 1, "time": "2026-10-11T12:00:05.123Z", "event": "exec.run", "env": "env-0123456789abcdef", "via": "cli", "outcome": "succeeded",
                 "detail": {"program": "npm", "commandLength": 8, "commandHash": "abc", "exitCode": 0}},
                {"seq": 2, "time": "2026-10-11T12:01:00.000Z", "event": "lockdown.applied", "env": null, "via": "policy", "outcome": "failed", "detail": {"level": "internet cut"}}]});
        let view = audit(&result, &Value::Null, false);
        assert!(view.contains("changed, reordered or truncated") && view.contains("record #7: record was changed"), "{view}");
        assert!(view.contains("audit.truncated") && view.contains("2026-10-11 12:00:05") && view.contains("env-0123456789abcdef"), "{view}");
        // An environment that still exists is shown by name.
        let named = audit(&result, &json!({"environments":[{"id":"env-0123456789abcdef","name":"web"}]}), false);
        assert!(named.contains(" web ") && !named.contains("env-0123"), "{named}");
        assert!(view.contains("program=npm") && !view.contains("commandHash"), "{view}");
        assert!(view.contains("failed  level=internet cut") && view.contains("2 records shown"), "{view}");
        let intact = audit(&json!({"count": 0, "records": [], "verification": {"ok": true, "records": 5, "firstSeq": 1, "lastSeq": 5, "segments": 1, "anchoredSeq": 5}}), &Value::Null, false);
        assert!(intact.contains("Chain intact") && intact.contains("#1–#5") && intact.contains("No matching records"), "{intact}");
    }

    #[test]
    fn lockdown_and_unlock_summaries_name_each_step_and_the_way_back() {
        let locked = json!({"all": true, "environments": [
            {"id": "env-1", "name": "codex", "ok": true, "steps": [{"step": "cutInternet", "ok": true}, {"step": "pause", "ok": true}]},
            {"id": "env-2", "name": "box", "skipped": "cloud servers run outside Yougori"},
            {"id": "env-3", "name": "vm", "ok": false, "steps": [{"step": "pause", "ok": false, "error": "busy"}]},
            {"id": "env-4", "name": "idle", "ok": true, "steps": []}]});
        let view = containment(&locked, false, false);
        assert!(view.contains("codex: Internet cut, paused") && view.contains("box: skipped"), "{view}");
        assert!(view.contains("vm: could not complete \"paused\": busy (failed)") && view.contains("idle: already contained"), "{view}");
        assert!(view.contains("yougori unlock --all --yes"), "{view}");
        let unlocked = json!({"all": false, "environments": [{"id": "env-1", "name": "codex", "unlocked": true, "ok": true,
            "steps": [{"step": "restoreInternet", "ok": true}, {"step": "resume", "ok": true}]}, {"id": "env-5", "unlocked": false}]});
        let view = containment(&unlocked, true, false);
        assert!(view.contains("codex: Internet restored, resumed") && view.contains("env-5: was not locked down") && view.contains("30 minutes"), "{view}");
    }

    #[test]
    fn status_and_top_show_security_only_when_the_engine_reports_it() {
        assert_eq!(security_line(&Value::Null, false), "");
        let line = security_line(&json!({"monitoring": true, "alerts": 1, "contained": [{"name": "codex"}]}), false);
        assert!(line.contains("monitoring on") && line.contains("1 alert  ·  1 contained") && line.contains("yougori monitor"), "{line}");
        let snapshot = json!({"host": {}, "environments": [{"name": "codex", "type": "microvm", "blocked": 3, "security": "locked down"}],
            "security": {"monitoring": false, "alerts": 0, "contained": []}});
        let view = top(&snapshot, false);
        assert!(view.contains("BLOCKED") && view.contains("SECURITY") && view.contains("locked down") && view.contains("monitoring off"), "{view}");
    }
}

#[cfg(test)]
mod views {
    use super::*;
    use serde_json::json;
    fn plain(text: &str) -> bool {
        // Words and box-drawing rules only: no check marks, crosses or decorative arrows.
        !text.chars().any(|c| matches!(c, '\u{2713}' | '\u{2714}' | '\u{2717}' | '\u{00d7}' | '\u{2192}' | '\u{2190}' | '\u{21b3}'))
    }
    #[test]
    fn environment_details_read_as_labelled_words() {
        let env = json!({"id":"env-1","name":"web","kind":"container","provider":"yougoriOci","status":"running","runtime":"nginx:1.27",
            "resourcePolicy":{"cpu":{"min":2.0,"max":2.0},"memoryGb":{"min":1.0,"max":4.0}},"cpuUsage":3.0,"memoryUsageGb":0.5,
            "storageLimitGb":20.0,"networkAccess":true,"gpuAccess":false,"createdAt":"2026-10-19T23:01:57.18Z","lastError":null});
        let text = details(&env, false);
        for expected in ["WEB", "Status", "running", "container", "nginx:1.27", "2 cores", "1 to 4 GB", "using 0.5 GB", "20 GB limit", "Internet", "on", "2026-10-19 23:01", "env-1"] {
            assert!(text.contains(expected), "{expected} in {text}");
        }
        assert!(!text.contains("Last error"), "an empty field is left out");
        assert!(!text.contains('{') && plain(&text));
    }
    #[test]
    fn empty_lists_say_what_to_do_next() {
        let state = json!({"environments":[]});
        assert!(snapshots(&json!([]), &state, false).contains("yougori snapshot create ENV --name NAME --yes"));
        assert!(backups(&json!([]), &state, false).contains("yougori backup run ENV"));
        assert!(destinations(&json!([]), false).contains("yougori backup add-destination"));
        assert!(shares(&json!([]), "web", false).contains("yougori share add web --path PC_FOLDER --yes"));
        assert!(images(&json!([]), false).contains("yougori pull IMAGE"));
        assert!(logs(&json!({"logs":""}), "web", false).contains("yougori logs web --follow"));
        // The window keeps the start of the tail, so what did not fit is the newer output.
        let cut = logs(&json!({"logs":"first
","truncated":true,"nextCursor":"eyJvIjoxfQ"}), "web", false);
        assert!(cut.contains("Newer output did not fit") && cut.contains("yougori logs web --cursor eyJvIjoxfQ"), "{cut}");
        assert!(logs(&json!({"logs":"first","truncated":true}), "web", false).contains("yougori logs web --limit 65536"));
        assert!(gpu(&json!({"supported":true,"installed":false}), false).contains("yougori gpu setup --yes"));
        assert!(connections(&json!([]), &state, false).contains("--source SOURCE_ID --target TARGET_ID"));
        let listing = services(&json!({"services":[],"publications":[],"notice":"Start this environment to discover listening services or publish ports."}), "web", false);
        assert!(listing.contains("Nothing is listening yet") && listing.contains("yougori ports publish web") && listing.contains("Start this environment"));
    }
    #[test]
    fn lists_show_names_not_only_ids() {
        let state = json!({"environments":[{"id":"env-1","name":"web"}],"destinations":[{"id":"dest-1","name":"Offsite"}]});
        let snaps = snapshots(&json!([{"id":"snap-1","environmentId":"env-1","name":"before-change","createdAt":"2026-10-20T08:00:00Z","sizeGb":1.25,"status":"ready"}]), &state, false);
        assert!(snaps.contains("before-change") && snaps.contains("web") && snaps.contains("1.2 GB") && snaps.contains("2026-10-20 08:00"), "{snaps}");
        let runs = backups(&json!([{"id":"b-1","environmentId":"env-1","destinationId":"dest-1","createdAt":"2026-10-20T08:00:00Z","transferredGb":0.5,"status":"complete"}]), &state, false);
        assert!(runs.contains("web") && runs.contains("Offsite") && runs.contains("complete"), "{runs}");
        let links = connections(&json!([{"id":"c-1","sourceId":"env-1","targetId":"env-2","ports":["5432"],"active":true}]), &state, false);
        assert!(links.contains("web") && links.contains("env-2") && links.contains("5432") && links.contains("active"), "{links}");
        let job_list = jobs(&json!([{"jobId":"job-1","method":"run_workload","status":"running","createdAt":"2026-10-20T08:00:00Z"}]), false);
        assert!(job_list.contains("Starting the workload") && !job_list.contains("run_workload"), "{job_list}");
        let shared = shares(&json!([{"id":"share-1","path":"C:/Projects/site","mountPath":"/workspace","readOnly":true}]), "web", false);
        assert!(shared.contains("C:/Projects/site") && shared.contains("view only"), "{shared}");
        let listed = images(&json!([{"Repository":"docker.io/library/nginx","Tag":"1.27","Size":"72MB","CreatedSince":"2 weeks ago"}]), false);
        assert!(listed.contains("docker.io/library/nginx:1.27") && listed.contains("72MB"), "{listed}");
        let files = folder(&json!({"path":"/app","entries":[{"name":"src","directory":true},{"name":"main.py","directory":false,"size":2048}]}), "web", false);
        assert!(files.contains("src/") && files.contains("folder") && files.contains("2.0 KB"), "{files}");
        for view in [snaps, runs, links, job_list, shared, listed, files] {
            assert!(plain(&view), "{view}");
        }
    }
    #[test]
    fn neocloud_pods_keep_their_own_state_words_and_never_read_as_free() {
        let state = json!({"environments":[]});
        let pods = json!({
            "env-1":{"name":"trainer","provider":"runpod","state":"Running","location":"EU-RO-1","extra":{"hourlyUsd":0.44}},
            "env-2":{"name":"idle","provider":"runpod","state":"Stopped","extra":{"hourlyUsd":0.44}},
            "env-3":{"name":"gone","provider":"runpod","state":"Delete requested — verification pending"}
        });
        let text = neocloud_pods(&pods, &state, false);
        assert!(text.contains("$0.44 per hour") && text.contains("Stopped") && text.contains("Delete requested — verification pending"), "{text}");
        assert_eq!(text.matches("$0.44").count(), 1, "a stopped pod shows no price: {text}");
        assert!(!text.contains("$0.00"));
        assert!(neocloud_pods(&json!({}), &state, false).contains("Sandboxes, New environment, Neocloud"));
    }
    #[test]
    fn model_views_read_in_words() {
        let status = model_status(&json!({"status":"freeing_memory","model":"TinyLlama/test","error":null,"download":{"receivedBytes":512,"totalBytes":1024}}), false);
        assert!(status.contains("freeing memory") && status.contains("50%"), "{status}");
        let access = model_access(&json!({"model":"TinyLlama/test","apiKey":"yk-1","apiUrl":"http://127.0.0.1:8000","publicUrl":null}), false);
        assert!(access.contains("http://127.0.0.1:8000") && access.contains("off") && access.contains("Keep the API key private"), "{access}");
        assert!(model_usage(&json!({"totals":{"requests":3,"prompt_tokens":10,"completion_tokens":20}}), false).contains("Reply tokens"));
        assert!(remote_shares(&json!({"grants":[]}), false).contains("yougori remote create"));
        assert!(domains(&json!([{"id":"d-1","hostname":"app.example.com","port":80,"hostPort":8080}]), false).contains("app.example.com"));
    }
    #[test]
    fn gpu_status_reads_in_words() {
        let missing = gpu(&json!({"supported":true,"installed":false,"running":false,"updateAvailable":false,"detail":"","checks":[{"name":"Driver","passed":true,"detail":"NVIDIA 571"}]}), false);
        assert!(missing.contains("not installed") && missing.contains("Driver") && missing.contains("passed") && missing.contains("yougori gpu setup"), "{missing}");
        assert!(gpu(&json!({"supported":false}), false).contains("not supported on this computer"));
    }
}
