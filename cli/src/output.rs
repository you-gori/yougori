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
    output.push_str(&styled("  ◆  YOUGORI", BRAND, color));
    output.push_str("\n  ");
    output.push_str(&styled("Your compute, one command", MUTED, color));
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
        assert!(rendered.starts_with("  ◆  YOUGORI\n  Your compute, one command"));
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
    let mut output = format!("{}\n", styled("×  Yougori could not complete the command", BAD, color));
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
            if color && status && matches!(headers[i], "STATUS" | "STATE") {
                styled(&padded, tone(cell), true)
            } else if color && status && headers[i].is_empty() {
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
        _ => None,
    }
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
        let (mark, text, style) = if ok { ("✓", good, GOOD) } else { ("!", attention, WARN) };
        output.push_str(&format!("{} {text}\n", styled(mark, style, color)));
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

/// The short name people type for a worker, such as keen-heron.
fn worker_handle(worker: &Value) -> String {
    worker["id"].as_str().map(yougori_cli::bounty::worker_handle).unwrap_or_else(|| "—".into())
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
    // Commands name the worker by its short name; the ID stays in the card for reference.
    let handle = worker_handle(worker);
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
    let mut rows = vec![
        ("Name", text(&worker["name"])),
        ("Worker", handle.clone()),
        ("State", state.clone()),
        ("Model", worker_model(worker)),
        ("Runs on", runs.join(" · ")),
        ("Workspace", worker["workspaceQuotaGb"].as_f64().map_or_else(|| "—".into(), |gb| format!("{gb} GB for bounty workspaces"))),
        ("Model memory", match worker["keepResident"].as_bool() {
            Some(true) => "kept loaded while waiting".into(),
            Some(false) => "loaded only for work".into(),
            None => "—".into(),
        }),
    ];
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
    if rows.is_empty() { output.push_str("Nothing is published. Publish a port with `yougori ports publish ENV --port N --kind local|cloudflare`.\n"); }
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
    let state = if snapshot["monitoring"] == false { styled("● Monitoring off", WARN, color) } else { styled("● Monitoring on", GOOD, color) };
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

/// `yougori audit`: optional chain check, then records oldest first.
pub fn audit(result: &Value, color: bool) -> String {
    let mut output = String::new();
    let verification = &result["verification"];
    if verification.is_object() {
        output.push_str(&section("Audit log check", color));
        if verification["ok"] == true {
            output.push_str(&format!("{}  {} records (#{}–#{}) in {} segments, anchored at #{}\n",
                styled("✓ Chain intact", GOOD, color), count(&verification["records"]), count(&verification["firstSeq"]),
                count(&verification["lastSeq"]), count(&verification["segments"]), count(&verification["anchoredSeq"])));
        } else {
            output.push_str(&format!("{}\n", styled("✗ The log was changed, reordered or truncated outside Yougori", BAD, color)));
            for problem in verification["problems"].as_array().into_iter().flatten().take(10) {
                let place = problem["seq"].as_u64().map(|seq| format!("record #{seq}: ")).unwrap_or_default();
                output.push_str(&format!("  {place}{}\n", safe(&text(&problem["problem"]))));
            }
        }
        for incident in verification["incidents"].as_array().into_iter().flatten() {
            output.push_str(&styled(&format!("! #{} {}: {}\n", count(&incident["seq"]), safe(&text(&incident["event"])), safe(&incident["detail"].to_string())), WARN, color));
        }
        for warning in verification["warnings"].as_array().into_iter().flatten() {
            output.push_str(&styled(&format!("  note: {}\n", safe(&text(&warning["warning"]))), MUTED, color));
        }
        output.push('\n');
    }
    output.push_str(&section("Audit log", color));
    let rows: Vec<Vec<String>> = result["records"].as_array().into_iter().flatten().map(|record| vec![
        short_time(&record["time"]), record["env"].as_str().map(|id| id.chars().take(12).collect()).unwrap_or_else(|| "—".into()),
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
            styled(&format!("– {}: skipped ({})", safe(&name), safe(reason)), MUTED, color)
        } else if let Some(error) = env["error"].as_str() {
            styled(&format!("✗ {}: {}", safe(&name), safe(error)), BAD, color)
        } else if unlock && env["unlocked"] == false {
            styled(&format!("– {}: was not locked down", safe(&name)), MUTED, color)
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
            styled(&format!("{} {}: {}", if ok { "✓" } else { "✗" }, safe(&name), safe(&summary)), if ok { GOOD } else { BAD }, color)
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
        let detail = match c["fix"].as_str() { Some(fix) => format!("{} → {fix}", text(&c["detail"])), None => text(&c["detail"]) };
        vec![status.into(), text(&c["name"]), detail]
    }).collect();
    let verdict = if report["ready"] == true { "Ready" } else { "Needs attention — fix the FAIL checks first" };
    let verdict_color = if report["ready"] == true { GOOD } else { BAD };
    format!("{}{}\n{}\n", section("System check", color), table(&["", "CHECK", "DETAIL"], &rows, color), styled(verdict, verdict_color, color))
}

pub fn status(overview: &Value, color: bool) -> String {
    if overview["engine"]["running"] != true {
        return format!("{}{}\n{}\n", section("Yougori status", color), styled("● Engine is offline", BAD, color), safe(&text(&overview["hint"])));
    }
    let envs = &overview["environments"];
    let types = envs["byType"].as_object().map(|t| t.iter().map(|(k, v)| format!("{v} {k}")).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    let sharing = &overview["sharing"];
    let domains = overview["savedDomains"].as_array().map(|d| d.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).filter(|d| !d.is_empty()).unwrap_or_else(|| "none".into());
    let mut output = format!(
        "{}{}  Engine {}\n{} environments  ·  {} running  ·  {} connections  ·  {} active jobs\n",
        section("Yougori status", color), styled("● Online", GOOD, color), safe(&text(&overview["engine"]["version"])), envs["total"], envs["running"], overview["connections"], overview["activeJobs"],
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
        assert!(doctor.contains("CHECKS") && doctor.contains("! Not registered with yougori.com yet") && doctor.contains("✓ Model API stays private"), "{doctor}");
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
        let view = audit(&result, false);
        assert!(view.contains("changed, reordered or truncated") && view.contains("record #7: record was changed"), "{view}");
        assert!(view.contains("audit.truncated") && view.contains("2026-10-11 12:00:05") && view.contains("env-01234567"), "{view}");
        assert!(view.contains("program=npm") && !view.contains("commandHash"), "{view}");
        assert!(view.contains("failed  level=internet cut") && view.contains("2 records shown"), "{view}");
        let intact = audit(&json!({"count": 0, "records": [], "verification": {"ok": true, "records": 5, "firstSeq": 1, "lastSeq": 5, "segments": 1, "anchoredSeq": 5}}), false);
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
        assert!(view.contains("✓ codex: Internet cut, paused") && view.contains("– box: skipped"), "{view}");
        assert!(view.contains("✗ vm: could not complete \"paused\": busy") && view.contains("idle: already contained"), "{view}");
        assert!(view.contains("yougori unlock --all --yes"), "{view}");
        let unlocked = json!({"all": false, "environments": [{"id": "env-1", "name": "codex", "unlocked": true, "ok": true,
            "steps": [{"step": "restoreInternet", "ok": true}, {"step": "resume", "ok": true}]}, {"id": "env-5", "unlocked": false}]});
        let view = containment(&unlocked, true, false);
        assert!(view.contains("✓ codex: Internet restored, resumed") && view.contains("env-5: was not locked down") && view.contains("30 minutes"), "{view}");
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
