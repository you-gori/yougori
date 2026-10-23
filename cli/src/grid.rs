//! Closed Neo Grid commands that take the company password: joining a company's grid
//! (`yougori COMPANY --neogrid --ip HUB_IP`, or with the admin's invite), creating one and
//! changing its password. The password comes from a hidden prompt or stdin (`--password -`),
//! never from arguments, which process listings and shell history keep. Other grid commands go
//! through `parse`; `yougori create grid` and `yougori join grid` ask questions instead.
use crate::{client, public::call};
use serde_json::{json, Value};
use std::io::{IsTerminal, Read, Write};

pub const USAGE: &str = "Usage: yougori create grid      (asks a few questions)
       yougori join grid        (asks for the invite and the password)
       yougori grid join --invite INVITE [--password -] [--name NAME]
       yougori COMPANY --neogrid --ip HUB_IP [--password | --password -] [--port 7460] [--name NAME] [--fingerprint SHA256]
       yougori grid join COMPANY --ip HUB_IP|https://TUNNEL [--password -] [--port 7460] [--name NAME] [--fingerprint SHA256]
       yougori grid create COMPANY --ip THIS_PC_IP [--tunnel quick|DOMAIN] [--password -] [--port 7460] [--hostname NAME] --yes
       yougori grid password [--password -] --yes
       yougori grid
       yougori desks create COMPANY --ip THIS_PC_IP [--tunnel quick|DOMAIN] [--password -] --yes
       yougori desks join --invite INVITE [--password -] [--name NAME]
       yougori desks add-person --username USER [--name NAME] [--password -]
       yougori desks person-password USER [--password -] --yes
       yougori desk login --invite INVITE --username USER [--password -] [--code 123456]
       yougori desk login --invite INVITE --sso
       yougori desks | desk";

/// `--neogrid` anywhere, or `grid` alone or with an action that takes the password.
pub fn requested(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--neogrid")
        || args.first().is_some_and(|word| word == "grid") && matches!(args.get(1).map(String::as_str), None | Some("create" | "join" | "password"))
        || args.first().is_some_and(|word| word == "desks") && matches!(args.get(1).map(String::as_str), None | Some("create" | "join" | "add-person" | "person-password"))
        || args.first().is_some_and(|word| word == "desk") && matches!(args.get(1).map(String::as_str), None | Some("login"))
}

#[derive(Debug, Default, PartialEq)]
struct Options {
    words: Vec<String>,
    neogrid: bool,
    yes: bool,
    /// `None`: not given; `Some(None)`: prompt; `Some(Some("-"))`: stdin.
    password: Option<Option<String>>,
    values: std::collections::BTreeMap<String, String>,
}

fn options(args: &[String]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let Some(flag) = arg.strip_prefix("--") else {
            options.words.push(arg.clone());
            index += 1;
            continue;
        };
        let (name, inline) = flag.split_once('=').map_or((flag, None), |(name, value)| (name, Some(value.to_owned())));
        match name {
            "neogrid" if inline.is_none() => options.neogrid = true,
            "yes" if inline.is_none() => options.yes = true,
            "sso" if inline.is_none() => {
                options.values.insert("sso".into(), "true".into());
            }
            "password" => {
                let value = inline.or_else(|| args.get(index + 1).filter(|next| !next.starts_with("--")).inspect(|_| index += 1).cloned());
                if value.as_deref().is_some_and(|value| value != "-") {
                    return Err("Never type the password into the command: leave it out to be asked for it, or use --password - to read it from stdin.".into());
                }
                options.password = Some(value);
            }
            // Every valued option a command below reads; `only` then says which ones apply.
            "ip" | "port" | "name" | "fingerprint" | "hostname" | "invite" | "tunnel" | "username" | "code" | "kind" | "cpu" | "memory-gb" | "disk-gb" | "gpu" => {
                let value = inline.or_else(|| args.get(index + 1).filter(|next| !next.starts_with("--")).inspect(|_| index += 1).cloned());
                let value = value.filter(|value| !value.trim().is_empty()).ok_or_else(|| format!("--{name} needs a value"))?;
                if options.values.insert(name.to_owned(), value).is_some() {
                    return Err(format!("--{name} is given twice. Use it once; the second one would be ignored and that is not worth guessing at."));
                }
            }
            _ => return Err(format!("Unknown option --{name}.\n{USAGE}")),
        }
        index += 1;
    }
    Ok(options)
}

/// What a person is told when they leave a password prompt. Nothing has been sent anywhere at
/// this point, and saying so is the whole of what they want to know.
pub(crate) const CANCELLED: &str = "Cancelled. Nothing was changed.";

/// A person types the password without it showing; `confirm` asks twice.
pub(crate) fn hidden(prompt: &str) -> Result<String, String> {
    use crossterm::event::{read, Event, KeyCode, KeyEventKind, KeyModifiers};
    struct Raw;
    impl Drop for Raw {
        fn drop(&mut self) {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
    // Nothing appears as it is typed, which is the point and is also exactly what a terminal
    // that has stopped responding looks like. Saying so once, before the cursor sits there, is
    // the difference between waiting and pressing keys to see whether anything is alive.
    eprint!("{prompt}");
    std::io::stderr().flush().map_err(|_| "Cannot ask for the password")?;
    crossterm::terminal::enable_raw_mode().map_err(|_| "Cannot read a hidden password in this terminal; use --password - and stdin")?;
    let _raw = Raw;
    let mut value = String::new();
    loop {
        if let Event::Key(key) = read().map_err(|_| "Cannot read the password")? {
            if key.kind == KeyEventKind::Release {
                continue;
            }
            match key.code {
                KeyCode::Enter => {
                    eprintln!("\r");
                    return Ok(value);
                }
                // Leaving the prompt is a cancellation, not a failure: said calmly, exit 130.
                KeyCode::Esc => {
                    eprintln!("\r");
                    return Err(crate::wire::cancelled(CANCELLED));
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    eprintln!("\r");
                    return Err(crate::wire::cancelled(CANCELLED));
                }
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char(c) if !c.is_control() && value.chars().count() < 256 => value.push(c),
                _ => {}
            }
        }
    }
}

/// One line from stdin, at most 1 KiB.
pub(crate) fn stdin_line(input: &mut impl Read) -> Result<String, String> {
    let mut bytes = Vec::new();
    input.take(1025).read_to_end(&mut bytes).map_err(|_| "Cannot read the password from stdin")?;
    if bytes.len() > 1024 {
        return Err("The password input exceeds 1 KiB".into());
    }
    let text = String::from_utf8(bytes).map_err(|_| "The password must be UTF-8 text")?;
    Ok(text.lines().next().unwrap_or_default().to_owned())
}

fn password(options: &Options, confirm: bool) -> Result<String, String> {
    match &options.password {
        Some(Some(_)) => stdin_line(&mut std::io::stdin().lock()),
        _ if std::io::stdin().is_terminal() => {
            let first = hidden("Company password (hidden): ")?;
            if confirm && hidden("Type it again: ")? != first {
                return Err("The passwords do not match; nothing was changed".into());
            }
            Ok(first)
        }
        _ => Err("Not in a terminal: supply the password on stdin with --password -".into()),
    }
}

fn port(options: &Options, params: &mut Value) -> Result<(), String> {
    if let Some(port) = options.values.get("port") {
        params["port"] = json!(port.parse::<u16>().ok().filter(|port| *port > 0).ok_or("--port must be between 1 and 65535")?);
    }
    Ok(())
}

fn only(options: &Options, allowed: &[&str]) -> Result<(), String> {
    match options.values.keys().find(|name| !allowed.contains(&name.as_str())) {
        Some(name) => Err(format!("--{name} does not apply here.\n{USAGE}")),
        None => Ok(()),
    }
}

async fn join_invite(options: &Options) -> Result<Value, String> {
    only(options, &["invite", "name"])?;
    let invite = options.values.get("invite").ok_or("--invite INVITE is required")?;
    let secret = password(options, false)?;
    let mut params = json!({"invite": invite, "password": secret});
    if let Some(name) = options.values.get("name") {
        params["name"] = json!(name);
    }
    client::start(None).await?;
    call("grid_join", params).await
}

async fn join(company: &str, options: &Options) -> Result<Value, String> {
    only(options, &["ip", "port", "name", "fingerprint"])?;
    let address = options.values.get("ip").ok_or("--ip HUB_IP is required: the address of the company's grid hub, such as 10.0.0.5")?;
    let secret = password(options, false)?;
    let mut params = json!({"company": company, "address": address, "password": secret});
    port(options, &mut params)?;
    for key in ["name", "fingerprint"] {
        if let Some(value) = options.values.get(key) {
            params[key] = json!(value);
        }
    }
    client::start(None).await?;
    call("grid_join", params).await
}

pub async fn run(args: &[String]) -> Result<Value, String> {
    let options = options(args)?;
    if options.neogrid {
        let [company] = options.words.as_slice() else {
            return Err(format!("Name the company once, before --neogrid.\n{USAGE}"));
        };
        return join(company, &options).await;
    }
    let words: Vec<&str> = options.words.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["grid"] => {
            only(&options, &[])?;
            client::start(None).await?;
            call("grid_status", json!({})).await
        }
        ["grid", "join"] => join_invite(&options).await,
        ["grid", "join", company] => join(company, &options).await,
        ["grid", "create", company] => {
            only(&options, &["ip", "port", "hostname", "tunnel"])?;
            let address = options.values.get("ip").ok_or("--ip is required: this computer's LAN or VPN address, which company computers will join")?;
            if !options.yes {
                return Err("Creating a grid opens a service on this computer's network address that computers with the company password can join. Repeat with --yes only if this is intended.".into());
            }
            let secret = password(&options, true)?;
            let mut params = json!({"name": company, "address": address, "password": secret});
            port(&options, &mut params)?;
            if let Some(hostname) = options.values.get("hostname") {
                params["hostname"] = json!(hostname);
            }
            if let Some(tunnel) = options.values.get("tunnel") {
                params["tunnel"] = json!(tunnel);
            }
            client::start(None).await?;
            call("grid_create", params).await
        }
        ["grid", "password"] => {
            only(&options, &[])?;
            if !options.yes {
                return Err("Computers will need the new password to join. Repeat with --yes only if this is intended.".into());
            }
            let secret = password(&options, true)?;
            client::start(None).await?;
            call("grid_password", json!({"password": secret})).await
        }
        ["desks"] | ["desk"] => {
            only(&options, &[])?;
            client::start(None).await?;
            call("desks_status", json!({})).await
        }
        ["desks", "create", company] => {
            only(&options, &["ip", "tunnel"])?;
            let address = options.values.get("ip").ok_or("--ip is required: this computer's LAN or VPN address, which company computers will join")?;
            if !options.yes {
                return Err("Hosting a sandbox grid opens a service on this computer's network address that computers with the password can join. Repeat with --yes only if this is intended.".into());
            }
            let secret = password(&options, true)?;
            client::start(None).await?;
            call("desks_create", json!({"name": company, "address": address, "password": secret, "tunnel": options.values.get("tunnel")})).await
        }
        ["desks", "join"] => {
            only(&options, &["invite", "name"])?;
            let invite = options.values.get("invite").ok_or("--invite INVITE is required: the sandbox grid invite your admin shared")?;
            let secret = password(&options, false)?;
            client::start(None).await?;
            call("desks_join", json!({"invite": invite, "password": secret, "name": options.values.get("name")})).await
        }
        ["desks", "add-person"] => {
            only(&options, &["username", "name", "kind", "cpu", "memory-gb", "disk-gb", "gpu"])?;
            let username = options.values.get("username").ok_or("--username USER is required: what the person signs in as")?;
            let number = |flag: &str| options.values.get(flag).map(|value| value.parse::<f64>().map_err(|_| format!("--{flag} must be a number"))).transpose();
            let gpu = options.values.get("gpu").map(|value| match value.as_str() { "true" | "yes" => Ok(true), "false" | "no" => Ok(false), _ => Err("--gpu must be true or false".to_owned()) }).transpose()?;
            let (cpu, memory, disk) = (number("cpu")?, number("memory-gb")?, number("disk-gb")?);
            let secret = password(&options, true)?;
            client::start(None).await?;
            call("desks_person_add", json!({"username": username, "name": options.values.get("name").unwrap_or(username), "password": secret, "kind": options.values.get("kind"), "cpu": cpu, "memoryGb": memory, "diskGb": disk, "gpu": gpu})).await
        }
        ["desks", "person-password", person] => {
            only(&options, &[])?;
            if !options.yes {
                return Err("The person will need the new password to sign in. Repeat with --yes only if this is intended.".into());
            }
            let secret = password(&options, true)?;
            client::start(None).await?;
            call("desks_person_password", json!({"person": person, "password": secret})).await
        }
        ["desk", "login"] => {
            only(&options, &["invite", "username", "code", "sso"])?;
            let invite = options.values.get("invite").ok_or("--invite INVITE is required: the sandbox grid invite your admin shared")?;
            if options.values.contains_key("sso") {
                // The company's identity provider signs them in; the browser opens on it.
                eprintln!("Opening your browser to sign in with your company account; come back here when it says you are signed in.");
                client::start(None).await?;
                return call("desk_login", json!({"invite": invite, "sso": true})).await;
            }
            let username = options.values.get("username").ok_or("--username USER is required, or --sso to sign in with your company account")?;
            let secret = password(&options, false)?;
            client::start(None).await?;
            call("desk_login", json!({"invite": invite, "username": username, "password": secret, "code": options.values.get("code")})).await
        }
        _ => Err(USAGE.into()),
    }
}

/// A hub that has not answered for a week: its person is asked whether to leave.
fn silence_line(member: &Value) -> Option<String> {
    let since = member["unreachableSince"].as_i64()?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs() as i64);
    let days = (now - since) / 86_400;
    (days >= 7).then(|| format!("            Its hub has not answered for {days} days. If it is gone for good, leave: `yougori grid leave --yes` (nothing here is removed)."))
}

/// How far off a Unix time is, in plain words: "in 2 d 5 h", "in 40 min", "now".
fn from_now(at: i64) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs() as i64);
    let left = at - now;
    if left <= 0 {
        return "now".into();
    }
    let (days, hours, minutes) = (left / 86_400, left % 86_400 / 3600, left % 3600 / 60);
    if days > 0 { format!("in {days} d {hours} h") } else if hours > 0 { format!("in {hours} h {minutes} min") } else { format!("in {} min", minutes.max(1)) }
}

/// The line a hub that is being deleted shows: paused until when, or how many computers heard.
fn closing_line(closing: &Value, restore: &str) -> Option<String> {
    let until = closing["until"].as_i64()?;
    let when = from_now(until);
    Some(if closing["gone"] == true {
        format!("Deleted     told {} of {} computers; the rest are told when they come back online", closing["told"].as_u64().unwrap_or(0), closing["computers"].as_u64().unwrap_or(0))
    } else {
        format!("Paused      deleted {when} unless restored: {restore}")
    })
}

/// Terminal text for joining and for the grid overview.
pub fn render(value: &Value) -> String {
    let mut lines: Vec<String> = value["message"].as_str().map(str::to_owned).into_iter().collect();
    if let Some(hub) = value["hub"].as_object() {
        let computers = &value["hub"]["computers"];
        lines.push(format!("Closed Neo Grid · {} (admin)", hub.get("name").and_then(Value::as_str).unwrap_or_default()));
        lines.extend(closing_line(&value["hub"]["closing"], "yougori grid restore"));
        lines.push(format!("Apps        {}  (API keys: yougori grid add-key --name APP)", value["hub"]["url"].as_str().unwrap_or_default()));
        lines.push(format!("Fingerprint {}", value["hub"]["fingerprint"].as_str().unwrap_or_default()));
        let tunnel = &value["hub"]["tunnel"];
        if tunnel.is_object() {
            let how = if tunnel["kind"] == "quick" { "Quick public link".to_owned() } else { tunnel["domain"].as_str().unwrap_or("your domain").to_owned() };
            match (tunnel["url"].as_str(), tunnel["error"].as_str()) {
                (Some(url), _) => lines.push(format!("Anywhere    {url}  ({how})")),
                (None, Some(error)) => lines.push(format!("Anywhere    {how} not connected: {error}")),
                (None, None) => lines.push(format!("Anywhere    {how} connecting…")),
            }
        }
        if let Some(invite) = value["hub"]["invite"].as_str() {
            lines.push(format!("Invite      {invite}"));
            lines.push("            Each company computer runs `yougori join grid` and pastes it; share the password separately.".into());
        }
        lines.push(format!(
            "Computers   {} joined · {} can run models · {} online",
            computers["total"].as_u64().unwrap_or(0),
            computers["capable"].as_u64().unwrap_or(0),
            computers["online"].as_u64().unwrap_or(0)
        ));
        let plans = value["hub"]["plans"].as_array().cloned().unwrap_or_default();
        if plans.is_empty() {
            lines.push("Plans       none · yougori grid add-plan --model hf.co/OWNER/MODEL --percent 50 --schedule \"Mon-Fri 18:00-08:00\"".into());
        }
        for plan in plans {
            lines.push(format!(
                "Plan        {} · {} · {}% → {}/{} computers, {} ready · {}",
                plan["id"].as_str().unwrap_or_default(),
                plan["model"].as_str().unwrap_or_default(),
                plan["percent"],
                plan["computers"],
                plan["target"],
                plan["ready"],
                plan["rules"].as_str().unwrap_or_default()
            ));
        }
        if let Some(warning) = value["hub"]["planWarning"].as_str() {
            lines.push(format!("            {warning}"));
        }
        for key in value["hub"]["keys"].as_array().into_iter().flatten() {
            lines.push(format!(
                "Key         {} · {} · {}… · {} requests, {} failed",
                key["id"].as_str().unwrap_or_default(),
                key["name"].as_str().unwrap_or_default(),
                key["prefix"].as_str().unwrap_or_default(),
                key["requests"],
                key["failures"]
            ));
        }
    }
    if let Some(error) = value["hubError"].as_str() {
        lines.push(format!("Hub         not running: {error}"));
    }
    if value["member"].is_object() {
        let member = &value["member"];
        lines.push(format!(
            "This computer  member of {} via {} · {}",
            member["grid"].as_str().unwrap_or_default(),
            member["hub"].as_str().unwrap_or_default(),
            if member["connected"] == true { "connected" } else { "not connected" }
        ));
        match member["assignment"].as_object() {
            Some(_) => lines.push(format!(
                "Assignment  {} · {}",
                member["assignment"]["model"].as_str().unwrap_or_default(),
                member["rules"].as_str().unwrap_or_default()
            )),
            None => lines.push(format!(
                "Assignment  none{}",
                if member["capable"] == false { " · this computer cannot run models (no supported GPU)" } else { " · the admin's plans have not picked this computer" }
            )),
        }
        if let Some(state) = member["state"].as_str().filter(|state| !state.is_empty()) {
            lines.push(format!("State       {state} · {}", member["reason"].as_str().unwrap_or_default()));
        }
        if let Some(error) = member["error"].as_str() {
            lines.push(format!("            {error}"));
        }
        if let Some(until) = member["pausedUntil"].as_i64() {
            let when = from_now(until);
            lines.push(format!("            Paused: the admin scheduled this grid for deletion {when}; nothing is removed unless that happens"));
        }
        lines.extend(silence_line(member));
        lines.push("Leave       yougori grid leave --yes".into());
    } else if let Some(error) = value["memberError"].as_str() {
        lines.push(format!("This computer  {error}"));
    }
    if lines.is_empty() {
        lines.push("Not in a Closed Neo Grid.\nJoin your company's grid:  yougori join grid\nAdmins create one with:   yougori create grid".into());
    }
    lines.join("\n")
}

/// Terminal text for the Sandbox Grid: the hub with its computers, people and desks; this
/// computer's membership and the desks it hosts; and its person's desk sign-in.
pub fn render_desks(value: &Value) -> String {
    let mut lines: Vec<String> = value["message"].as_str().map(str::to_owned).into_iter().collect();
    let plural = |n: usize, one: &str| if n == 1 { one.to_owned() } else { format!("{one}s") };
    if let Some(hub) = value["hub"].as_object() {
        let computers = &value["hub"]["computers"];
        lines.push(format!("Sandbox Grid · {} (admin)", hub.get("name").and_then(Value::as_str).unwrap_or_default()));
        lines.extend(closing_line(&value["hub"]["closing"], "yougori desks restore"));
        lines.push(format!("Address     {}:{}", value["hub"]["address"].as_str().unwrap_or_default(), value["hub"]["port"].as_u64().unwrap_or(0)));
        lines.push(format!("Fingerprint {}", value["hub"]["fingerprint"].as_str().unwrap_or_default()));
        let tunnel = &value["hub"]["tunnel"];
        if tunnel.is_object() {
            let how = if tunnel["kind"] == "quick" { "Quick public link".to_owned() } else { tunnel["domain"].as_str().unwrap_or("your domain").to_owned() };
            match (tunnel["url"].as_str(), tunnel["error"].as_str()) {
                (Some(url), _) => lines.push(format!("Anywhere    {url}  ({how})")),
                (None, Some(error)) => lines.push(format!("Anywhere    {how} not connected: {error}")),
                (None, None) => lines.push(format!("Anywhere    {how} connecting…")),
            }
        }
        if let Some(invite) = value["hub"]["invite"].as_str() {
            lines.push(format!("Invite      {invite}"));
            lines.push("            Each company computer runs `yougori desks join --invite INVITE`; share the password separately. Then set what the grid may take from each: yougori desks share MEMBER_ID --cpu N --memory-gb N --disk-gb N".into());
        }
        lines.push(format!("Computers   {} joined · {} online", computers["total"].as_u64().unwrap_or(0), computers["online"].as_u64().unwrap_or(0)));
        for computer in value["hub"]["members"].as_array().into_iter().flatten() {
            let capacity = &computer["capacity"];
            let hosting = computer["desks"].as_u64().unwrap_or(0) as usize;
            let whole = |key: &str| capacity[key].as_f64().unwrap_or(0.0).round();
            let state = if computer["online"] != true { "offline".to_owned() }
                else if capacity.is_null() { "waiting for its first report".to_owned() }
                else { format!("{} cores {}% busy · {} of {} GB memory used · {} GB disk free{}{}", capacity["cpu"].as_u64().unwrap_or(0), whole("cpuUsedPercent"), whole("usedMemoryGb"), whole("memoryGb"), whole("freeDiskGb"), match (capacity["gpu"] == true, capacity["gpuUsedPercent"].as_f64()) { (true, Some(used)) => format!(" · GPU {}% busy", used.round()), (true, None) => " · GPU".to_owned(), _ => String::new() }, if capacity["inUse"] == true { " · in use" } else { "" }) };
            lines.push(format!("Computer    {} · {} · {state} · {hosting} {}", computer["id"].as_str().unwrap_or_default(), computer["name"].as_str().unwrap_or_default(), plural(hosting, "desk")));
            let share = &computer["share"];
            if share.is_object() {
                let number = |key: &str| { let value = share[key].as_f64().unwrap_or(0.0); if value.fract() == 0.0 { format!("{}", value as i64) } else { format!("{value:.1}") } };
                lines.push(format!("            grid may use {} CPU · {} GB memory · {} GB disk{}{}{}", number("cpu"), number("memoryGb"), number("diskGb"), if share["gpu"] == true { " · GPU" } else { "" }, if share["idleOnly"] == true { " · only while nobody is using it" } else { "" }, if computer["shareSet"] == true { "" } else { " (suggested; yougori desks share MEMBER_ID --cpu N --memory-gb N --disk-gb N)" }));
            }
        }
        for person in value["hub"]["people"].as_array().into_iter().flatten() {
            let desks = person["desks"].as_array().map_or(0, Vec::len);
            lines.push(format!("Person      {} · {} · {desks} {}", person["username"].as_str().unwrap_or_default(), person["name"].as_str().unwrap_or_default(), plural(desks, "desk")));
        }
        for desk in value["hub"]["desks"].as_array().into_iter().flatten() {
            if desk["state"] == "moving" {
                let packed = desk["parcelBytes"].as_u64().map(|bytes| format!(" · {:.1} GB packed", bytes as f64 / 1_073_741_824.0)).unwrap_or_default();
                lines.push(format!("Desk        {} · {} · moving with its data{packed} · {}", desk["id"].as_str().unwrap_or_default(), desk["name"].as_str().unwrap_or_default(), desk["note"].as_str().unwrap_or_default()));
                continue;
            }
            lines.push(format!(
                "Desk        {} · {} · {} · {}{} · {}",
                desk["id"].as_str().unwrap_or_default(),
                desk["name"].as_str().unwrap_or_default(),
                desk["summary"].as_str().unwrap_or_default(),
                desk["person"].as_str().unwrap_or("nobody"),
                desk["host"].as_str().map(|host| format!(" · on {host}{}", if desk["hostOnline"] == true { "" } else { " (offline)" })).unwrap_or_default(),
                desk["note"].as_str().unwrap_or_default()
            ));
        }
        if value["hub"]["people"].as_array().is_none_or(Vec::is_empty) {
            lines.push("People      none · yougori desks add-person --username USER --name NAME".into());
        }
        if value["hub"]["desks"].as_array().is_none_or(Vec::is_empty) {
            lines.push("Desks       none · yougori desks add-desk --name NAME --person USER --cpu 2 --memory-gb 4 --disk-gb 20".into());
        }
    }
    if let Some(error) = value["hubError"].as_str() {
        lines.push(format!("Hub         not running: {error}"));
    }
    // The cloud computers the grid created on its own, shown even after the grid is deleted so
    // one that still costs money is never out of sight. The words are the page's.
    let cloud = &value["cloudFallback"];
    if let Some(error) = cloud["error"].as_str() {
        lines.push(format!("Cloud       {error}{}", cloud["retryAfter"].as_i64().map(|at| format!(" The next try is {}.", from_now(at))).unwrap_or_default()));
    }
    if let Some(note) = cloud["note"].as_str() {
        lines.push(format!("Cloud       {note}"));
    }
    if value["member"].is_object() {
        let member = &value["member"];
        lines.push(format!("This computer  member of {}'s sandbox grid via {} · {}", member["grid"].as_str().unwrap_or_default(), member["hub"].as_str().unwrap_or_default(), if member["connected"] == true { "connected" } else { "not connected" }));
        if let Some(error) = member["error"].as_str() {
            lines.push(format!("            {error}"));
        }
        if let Some(until) = member["pausedUntil"].as_i64() {
            let when = from_now(until);
            lines.push(format!("            Paused: the admin scheduled this grid for deletion {when}; nothing is removed unless that happens"));
        }
        lines.extend(silence_line(member).map(|line| line.replace("yougori grid leave", "yougori desks leave")));
        let hosting = value["hosting"].as_array().cloned().unwrap_or_default();
        lines.push(format!("Hosting     {} {}{}", hosting.len(), plural(hosting.len(), "desk"), if hosting.is_empty() { String::new() } else { format!(" · {}", hosting.iter().map(|desk| format!("{}{}", desk["name"].as_str().unwrap_or_default(), if desk["shared"] == true { "" } else { " (not shared yet)" })).collect::<Vec<_>>().join(", ")) }));
        lines.push("Leave       yougori desks leave --yes".into());
    } else if let Some(error) = value["memberError"].as_str() {
        lines.push(format!("This computer  {error}"));
    }
    if let Some(desk) = value["desk"].as_object() {
        lines.push(format!("Signed in   {} as {} ({})", desk.get("grid").and_then(Value::as_str).unwrap_or_default(), desk.get("name").and_then(Value::as_str).unwrap_or_default(), desk.get("username").and_then(Value::as_str).unwrap_or_default()));
        let desks = desk.get("desks").and_then(Value::as_array).cloned().unwrap_or_default();
        if desks.is_empty() {
            lines.push("Desks       none yet · ask your admin for one".into());
        }
        for entry in desks {
            // The desk's own name is already the first thing on this line, and it is the name
            // the sandbox list shows. The identifier beside it was a second name for the same
            // thing, in the one form nobody can read or remember.
            let open = entry["environmentId"].as_str().filter(|_| entry["state"] == "ready").map(|_| "open it from the sandbox list".to_owned()).unwrap_or_else(|| entry["note"].as_str().unwrap_or_default().to_owned());
            lines.push(format!("Desk        {} · {} · {}{}", entry["name"].as_str().unwrap_or_default(), entry["state"].as_str().unwrap_or_default(), open, entry["host"].as_str().map(|host| format!(" · on {host}")).unwrap_or_default()));
        }
        lines.push("Sign out    yougori desk logout --yes".into());
    }
    if lines.is_empty() {
        lines.push("Not in a Sandbox Grid.\nAdmins host one with:        yougori desks create COMPANY --ip THIS_PC_IP --yes\nCompany computers join with: yougori desks join --invite INVITE\nOpen your desk with:         yougori desk login --invite INVITE --username USER".into());
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(args: &[&str]) -> Result<Options, String> {
        options(&args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>())
    }
    fn words(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }
    #[test]
    fn the_company_join_command_reads_naturally() {
        let options = parse(&["acme", "--neogrid", "--password", "--ip", "10.0.0.5"]).unwrap();
        assert_eq!((options.words.as_slice(), options.neogrid, &options.password), (&["acme".to_owned()][..], true, &Some(None)));
        assert_eq!(options.values["ip"], "10.0.0.5");
        let piped = parse(&["acme", "--neogrid", "--ip=10.0.0.5", "--password", "-", "--port", "7461"]).unwrap();
        assert_eq!((piped.password, piped.values["port"].as_str()), (Some(Some("-".into())), "7461"));
        let trailing = parse(&["acme", "--neogrid", "--ip", "10.0.0.5", "--password"]).unwrap();
        assert_eq!(trailing.password, Some(None));
    }
    #[test]
    fn passwords_in_arguments_and_unknown_options_are_refused() {
        for args in [&["acme", "--neogrid", "--password", "hunter2", "--ip", "10.0.0.5"][..], &["acme", "--neogrid", "--password=hunter2"]] {
            assert!(parse(args).unwrap_err().contains("Never type the password"));
        }
        assert!(parse(&["acme", "--neogrid", "--colour"]).unwrap_err().contains("Unknown option"));
        assert!(parse(&["acme", "--neogrid", "--ip"]).unwrap_err().contains("needs a value"));
        assert!(parse(&["acme", "--ip", "1", "--ip", "2"]).unwrap_err().contains("twice"));
    }
    #[test]
    fn only_grid_password_commands_are_handled_here() {
        assert!(requested(&words(&["desks", "add-person", "--username", "ada"])) && requested(&words(&["desks", "create", "Acme"])) && requested(&words(&["desks"])) && requested(&words(&["desk", "login"])) && requested(&words(&["desk"])));
        assert!(!requested(&words(&["desk", "logout"])) && !requested(&words(&["desks", "add-desk"])) && !requested(&words(&["desks", "status"])));
        assert!(requested(&words(&["acme", "--neogrid"])));
        assert!(requested(&words(&["grid"])) && requested(&words(&["grid", "create", "Acme"])) && requested(&words(&["grid", "password"])));
        assert!(!requested(&words(&["grid", "status"])) && !requested(&words(&["grid", "add-plan"])) && !requested(&words(&["model", "run"])));
    }
    #[test]
    fn invites_and_tunnels_are_options() {
        let joined = parse(&["grid", "join", "--invite", "grid-invite:abc", "--password", "-"]).unwrap();
        assert_eq!((joined.words.as_slice(), joined.values["invite"].as_str()), (&["grid".to_owned(), "join".to_owned()][..], "grid-invite:abc"));
        let created = parse(&["grid", "create", "Acme", "--ip", "10.0.0.5", "--tunnel", "quick", "--yes"]).unwrap();
        assert_eq!((created.values["tunnel"].as_str(), created.yes), ("quick", true));
        assert!(only(&created, &["ip", "tunnel"]).is_ok() && only(&created, &["ip"]).is_err());
    }
    #[test]
    fn two_step_codes_and_desk_sizes_are_options() {
        let login = parse(&["desk", "login", "--invite", "desk-invite:abc", "--username", "ada", "--code", "123456"]).unwrap();
        assert_eq!(login.values["code"], "123456");
        assert!(only(&login, &["invite", "username", "code", "sso"]).is_ok());
        let person = parse(&["desks", "add-person", "--username", "ada", "--kind", "vm", "--cpu", "2", "--memory-gb", "4", "--disk-gb", "40", "--gpu", "false"]).unwrap();
        assert_eq!((person.values["cpu"].as_str(), person.values["gpu"].as_str()), ("2", "false"));
        assert!(only(&person, &["username", "name", "kind", "cpu", "memory-gb", "disk-gb", "gpu"]).is_ok());
        assert!(only(&person, &["username"]).is_err());
    }
    #[test]
    fn a_grid_being_deleted_says_so_for_the_admin_and_its_computers() {
        let soon = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 + 2 * 86_400 + 3700;
        let paused = render_desks(&json!({"hub":{"name":"Acme","address":"10.0.0.5","port":7463,"fingerprint":"AB","computers":{"total":1,"online":1},"members":[],"people":[],"desks":[],"closing":{"until":soon,"gone":false,"told":0,"computers":1}}}));
        assert!(paused.contains("Paused      deleted in 2 d 1 h unless restored: yougori desks restore"), "{paused}");
        let gone = render(&json!({"hub":{"name":"Acme","url":"https://10.0.0.5:7460/v1","fingerprint":"AB","computers":{"total":3,"capable":0,"online":1},"members":[],"plans":[],"keys":[],"closing":{"until":1,"gone":true,"told":2,"computers":3}}}));
        assert!(gone.contains("Deleted     told 2 of 3 computers"), "{gone}");
        let member = render_desks(&json!({"member":{"grid":"Acme","hub":"10.0.0.5:7463","connected":true,"pausedUntil":soon},"hosting":[]}));
        assert!(member.contains("Paused: the admin scheduled this grid for deletion in 2 d 1 h"), "{member}");
    }

    #[test]
    fn sandbox_grid_text_covers_the_admin_the_hosts_and_the_people() {
        assert!(render_desks(&json!({"hub":null,"member":null,"desk":null})).contains("yougori desks create"));
        let admin = json!({"hub":{"name":"Acme","address":"10.0.0.5","port":7463,"fingerprint":"AB","invite":"desk-invite:xyz","computers":{"total":2,"online":1},
            "members":[{"id":"m-1","name":"Design laptop","online":true,"desks":1,"capacity":{"cpu":8,"cpuUsedPercent":23.4,"memoryGb":32.0,"usedMemoryGb":11.6,"freeDiskGb":300.0,"gpu":false,"inUse":false},"share":{"cpu":4,"memoryGb":15,"diskGb":150,"gpu":false,"idleOnly":false},"shareSet":false},{"id":"m-2","name":"Studio PC","online":true,"desks":0,"capacity":{"cpu":16,"cpuUsedPercent":70.0,"memoryGb":64.0,"usedMemoryGb":40.0,"freeDiskGb":80.0,"gpu":true,"gpuUsedPercent":55.0,"inUse":true},"share":{"cpu":2,"memoryGb":4.5,"diskGb":20,"gpu":true,"idleOnly":true},"shareSet":true}],
            "people":[{"username":"ada.lovelace","name":"Ada Lovelace","desks":["desk-1"]}],
            "desks":[{"id":"desk-1","name":"Design desk","summary":"Container · 2 CPU · 4 GB memory · 20 GB disk","person":"Ada Lovelace","host":"Design laptop","hostOnline":true,"note":"Ready"}]},
            "member":{"grid":"Acme","hub":"10.0.0.5:7463","connected":true},"hosting":[{"name":"Design desk","shared":true}],
            "desk":{"grid":"Acme","name":"Ada Lovelace","username":"ada.lovelace","desks":[{"name":"Design desk","state":"ready","environmentId":"env-1","host":"Design laptop"}]}});
        let text = render_desks(&admin);
        for needle in ["Acme (admin)", "10.0.0.5:7463", "desk-invite:xyz", "8 cores 23% busy · 12 of 32 GB memory used · 300 GB disk free · 1 desk", "grid may use 4 CPU · 15 GB memory · 150 GB disk (suggested; yougori desks share", "16 cores 70% busy · 40 of 64 GB memory used · 80 GB disk free · GPU 55% busy · in use · 0 desks", "grid may use 2 CPU · 4.5 GB memory · 20 GB disk · GPU · only while nobody is using it\n", "ada.lovelace · Ada Lovelace · 1 desk", "Design desk · Container · 2 CPU", "member of Acme's sandbox grid", "Hosting     1 desk · Design desk", "Signed in   Acme as Ada Lovelace", "Design desk · ready · open it from the sandbox list"] {
            assert!(text.contains(needle), "{needle} in\n{text}");
        }
    }
    #[test]
    fn cloud_computers_stay_in_sight_after_their_grid_is_deleted() {
        let later = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 + 14 * 60 + 30;
        let text = render_desks(&json!({"hub":null,"member":null,"desk":null,"cloudFallback":{"computers":1,"error":"Cloud computer yougori-desk-1 could not be deleted: aws CLI: expired token. It may still cost money; delete it in Cloud deployments.","note":"This sandbox grid was deleted, so the cloud computer it created is being removed.","retryAfter":later,"held":false}}));
        assert!(text.contains("Cloud       Cloud computer yougori-desk-1 could not be deleted") && text.contains("The next try is in 14 min."), "{text}");
        assert!(text.contains("Cloud       This sandbox grid was deleted") && !text.contains("Not in a Sandbox Grid"), "{text}");
        assert!(!render_desks(&json!({"hub":null,"member":null,"desk":null,"cloudFallback":null})).contains("Cloud "));
    }
    #[test]
    fn stdin_passwords_are_one_bounded_line() {
        assert_eq!(stdin_line(&mut "correct horse\r\nignored".as_bytes()).unwrap(), "correct horse");
        assert!(stdin_line(&mut "x".repeat(2000).as_bytes()).is_err());
    }
    #[test]
    fn overview_text_covers_admins_members_and_newcomers() {
        assert!(render(&json!({"hub":null,"member":null})).contains("yougori join grid"));
        let tunneled = render(&json!({"hub":{"name":"Acme","url":"https://10.0.0.5:7460/v1","fingerprint":"AB","computers":{"total":1,"capable":1,"online":1},"plans":[],"keys":[],
            "tunnel":{"kind":"quick","url":"https://bright-lake.trycloudflare.com","connected":true},"invite":"grid-invite:xyz"},"member":null}));
        assert!(tunneled.contains("Anywhere    https://bright-lake.trycloudflare.com  (Quick public link)") && tunneled.contains("Invite      grid-invite:xyz"), "{tunneled}");
        let admin = json!({"hub":{"name":"Acme","url":"https://10.0.0.5:7460/v1","fingerprint":"AB","computers":{"total":3,"capable":2,"online":2},
            "plans":[{"id":"plan-1","model":"Qwen/Qwen3-8B","percent":50,"computers":1,"target":1,"ready":1,"rules":"Mon-Fri 18:00-08:00, after 15 min without keyboard or mouse input"}],
            "keys":[{"id":"key-1","name":"Analytics","prefix":"ygrid_abc123","requests":4,"failures":0}]},
            "member":{"grid":"Acme","hub":"10.0.0.5:7460","connected":true,"assignment":{"model":"Qwen/Qwen3-8B"},"rules":"Mon-Fri 18:00-08:00","state":"person_active","reason":"Someone is using this computer"}});
        let text = render(&admin);
        for needle in ["Acme (admin)", "https://10.0.0.5:7460/v1", "3 joined", "Qwen/Qwen3-8B · 50% → 1/1 computers", "Analytics", "member of Acme", "person_active"] {
            assert!(text.contains(needle), "{needle} in\n{text}");
        }
    }
}
