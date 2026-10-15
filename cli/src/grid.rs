//! Closed Neo Grid commands that take the company password: joining a company's grid
//! (`yougori COMPANY --neogrid --ip HUB_IP`), creating one and changing its password. The
//! password comes from a hidden prompt or stdin (`--password -`), never from arguments,
//! which process listings and shell history keep. Other grid commands go through `parse`.
use crate::{client, public::call};
use serde_json::{json, Value};
use std::io::{IsTerminal, Read, Write};

pub const USAGE: &str = "Usage: yougori COMPANY --neogrid --ip HUB_IP [--password | --password -] [--port 7460] [--name NAME] [--fingerprint SHA256]
       yougori grid join COMPANY --ip HUB_IP [--password -] [--port 7460] [--name NAME] [--fingerprint SHA256]
       yougori grid create COMPANY --ip THIS_PC_IP [--password -] [--port 7460] [--hostname NAME] --yes
       yougori grid password [--password -] --yes
       yougori grid";

/// `--neogrid` anywhere, or `grid` alone or with an action that takes the password.
pub fn requested(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--neogrid")
        || args.first().is_some_and(|word| word == "grid") && matches!(args.get(1).map(String::as_str), None | Some("create" | "join" | "password"))
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
            "password" => {
                let value = inline.or_else(|| args.get(index + 1).filter(|next| !next.starts_with("--")).inspect(|_| index += 1).cloned());
                if value.as_deref().is_some_and(|value| value != "-") {
                    return Err("Never type the password into the command: leave it out to be asked for it, or use --password - to read it from stdin.".into());
                }
                options.password = Some(value);
            }
            "ip" | "port" | "name" | "fingerprint" | "hostname" => {
                let value = inline.or_else(|| args.get(index + 1).filter(|next| !next.starts_with("--")).inspect(|_| index += 1).cloned());
                let value = value.filter(|value| !value.trim().is_empty()).ok_or_else(|| format!("--{name} needs a value"))?;
                if options.values.insert(name.to_owned(), value).is_some() {
                    return Err(format!("--{name} was specified twice"));
                }
            }
            _ => return Err(format!("Unknown option --{name}.\n{USAGE}")),
        }
        index += 1;
    }
    Ok(options)
}

/// A person types the password without it showing; `confirm` asks twice.
fn hidden(prompt: &str) -> Result<String, String> {
    use crossterm::event::{read, Event, KeyCode, KeyEventKind, KeyModifiers};
    struct Raw;
    impl Drop for Raw {
        fn drop(&mut self) {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
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
                KeyCode::Esc => return Err("Cancelled".into()),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Err("Cancelled".into()),
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
fn stdin_line(input: &mut impl Read) -> Result<String, String> {
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
        ["grid", "join", company] => join(company, &options).await,
        ["grid", "create", company] => {
            only(&options, &["ip", "port", "hostname"])?;
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
        _ => Err(USAGE.into()),
    }
}

/// Terminal text for joining and for the grid overview.
pub fn render(value: &Value) -> String {
    let mut lines: Vec<String> = value["message"].as_str().map(str::to_owned).into_iter().collect();
    if let Some(hub) = value["hub"].as_object() {
        let computers = &value["hub"]["computers"];
        lines.push(format!("Closed Neo Grid · {} (admin)", hub.get("name").and_then(Value::as_str).unwrap_or_default()));
        lines.push(format!("Apps        {}  (API keys: yougori grid add-key --name APP)", value["hub"]["url"].as_str().unwrap_or_default()));
        lines.push(format!("Fingerprint {}", value["hub"]["fingerprint"].as_str().unwrap_or_default()));
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
        lines.push("Leave       yougori grid leave --yes".into());
    } else if let Some(error) = value["memberError"].as_str() {
        lines.push(format!("This computer  {error}"));
    }
    if lines.is_empty() {
        lines.push("Not in a Closed Neo Grid.\nJoin your company's grid: yougori COMPANY --neogrid --ip HUB_IP\nAdmins create one with:  yougori grid create COMPANY --ip THIS_PC_IP --yes".into());
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
        assert!(requested(&words(&["acme", "--neogrid"])));
        assert!(requested(&words(&["grid"])) && requested(&words(&["grid", "create", "Acme"])) && requested(&words(&["grid", "password"])));
        assert!(!requested(&words(&["grid", "status"])) && !requested(&words(&["grid", "add-plan"])) && !requested(&words(&["model", "run"])));
    }
    #[test]
    fn stdin_passwords_are_one_bounded_line() {
        assert_eq!(stdin_line(&mut "correct horse\r\nignored".as_bytes()).unwrap(), "correct horse");
        assert!(stdin_line(&mut "x".repeat(2000).as_bytes()).is_err());
    }
    #[test]
    fn overview_text_covers_admins_members_and_newcomers() {
        assert!(render(&json!({"hub":null,"member":null})).contains("yougori COMPANY --neogrid --ip HUB_IP"));
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
