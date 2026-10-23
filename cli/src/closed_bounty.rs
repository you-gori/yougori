//! Hosting a Closed Bounty from the CLI: publish a source so other computers join with the company
//! password, choose their own model and work it; findings come back here. This is the publish side,
//! the counterpart to the Swarm Mining worker commands in `bounty.rs`. Like `grid create`, the
//! password comes from a hidden prompt or stdin (`--password -`), never from an argument.
//!
//! These verbs (`bounty host|hosted|remove-hunter|unhost`) are handled here, before the Swarm
//! worker CLI, so the one `bounty` word covers both roles. The host runs no model.
use crate::{grid, public::call};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path};

pub const USAGE: &str = if crate::distribution::LIVE_TARGETS { "Usage: yougori bounty host COMPANY --title TITLE --ip THIS_PC_IP [--source DIR] [--url URL [--health PATH]]
                               [--instructions TEXT] [--authorization TEXT] [--password -] --yes
                               (--source, --url or both: the files to review, a live service to test)
       yougori bounty hosted                 what is published, who joined, findings
       yougori bounty remove-hunter MEMBER_ID --yes
       yougori bounty unhost --yes" } else { "Usage: yougori bounty host COMPANY --title TITLE --ip THIS_PC_IP --source DIR
                               [--instructions TEXT] [--authorization TEXT] [--password -] --yes
                               (review the imported source inside an isolated sandbox)
       yougori bounty hosted                 what is published, who joined, findings
       yougori bounty remove-hunter MEMBER_ID --yes
       yougori bounty unhost --yes" };

/// The `bounty` verbs this module owns, so they never reach the Swarm worker parser.
pub fn requested(args: &[String]) -> bool {
    args.first().is_some_and(|word| word == "bounty")
        && matches!(args.get(1).map(String::as_str), Some("host" | "hosted" | "remove-hunter" | "unhost"))
}

#[derive(Debug, Default, PartialEq)]
struct Options {
    words: Vec<String>,
    yes: bool,
    /// `None`: not given; `Some(None)`: prompt; `Some(Some("-"))`: stdin.
    password: Option<Option<String>>,
    values: BTreeMap<String, String>,
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
            "yes" if inline.is_none() => options.yes = true,
            "password" => {
                let value = inline.or_else(|| args.get(index + 1).filter(|next| !next.starts_with("--")).inspect(|_| index += 1).cloned());
                if value.as_deref().is_some_and(|value| value != "-") {
                    return Err("Never type the password into the command: leave it out to be asked for it, or use --password - to read it from stdin.".into());
                }
                options.password = Some(value);
            }
            "title" | "ip" | "source" | "instructions" | "authorization" | "url" | "health" => {
                crate::distribution::check_live_target(matches!(name, "url" | "health"))?;
                let value = inline.or_else(|| args.get(index + 1).filter(|next| !next.starts_with("--")).inspect(|_| index += 1).cloned());
                let what = match name {
                    "title" => "the bounty's title",
                    "ip" => "this computer's LAN or VPN address",
                    "source" => "the folder of files to review",
                    "instructions" => "what the workers should focus on",
                    "authorization" => "your statement that you may authorize this review",
                    "url" => "the live service's address",
                    _ => "the service's health path, such as /health",
                };
                let value = value.ok_or_else(|| format!("--{name} needs a value: {what}."))?;
                if options.values.insert(name.to_owned(), value).is_some() {
                    return Err(format!("--{name} is given twice. Give it once."));
                }
            }
            _ => return Err(format!("Unknown option --{name}.\n{USAGE}")),
        }
        index += 1;
    }
    Ok(options)
}

fn password(options: &Options) -> Result<String, String> {
    use std::io::IsTerminal;
    match &options.password {
        Some(Some(_)) => grid::stdin_line(&mut std::io::stdin().lock()),
        _ if std::io::stdin().is_terminal() => {
            let first = grid::hidden("Company password (hidden): ")?;
            if grid::hidden("Type it again: ")? != first {
                return Err("The two passwords do not match. Nothing was changed; run it again.".into());
            }
            Ok(first)
        }
        _ => Err("Not in a terminal: supply the password on stdin with --password -".into()),
    }
}

fn only(options: &Options, allowed: &[&str]) -> Result<(), String> {
    match options.values.keys().find(|name| !allowed.contains(&name.as_str())) {
        Some(name) => Err(format!("--{name} does not apply here.\n{USAGE}")),
        None => Ok(()),
    }
}

pub async fn run(args: &[String]) -> Result<Value, String> {
    let options = options(&args[1..])?;
    let action = options.words.first().map(String::as_str).unwrap_or_default();
    let positionals = &options.words[options.words.len().min(1)..];
    match action {
        "hosted" => {
            if !positionals.is_empty() {
                return Err(USAGE.into());
            }
            only(&options, &[])?;
            crate::client::start(None).await?;
            call("bounty_status", json!({})).await
        }
        "unhost" => {
            only(&options, &[])?;
            if !positionals.is_empty() {
                return Err(USAGE.into());
            }
            if !options.yes {
                return Err("Computers working this bounty can no longer reach the host. Repeat with --yes only if this is intended.".into());
            }
            crate::client::start(None).await?;
            call("bounty_delete", json!({})).await
        }
        "remove-hunter" => {
            only(&options, &[])?;
            let [member] = positionals else {
                return Err("Usage: yougori bounty remove-hunter MEMBER_ID --yes (the ID is from yougori bounty hosted)".into());
            };
            if !options.yes {
                return Err("The computer stops working this bounty. Repeat with --yes only if this is intended.".into());
            }
            crate::client::start(None).await?;
            call("bounty_member_remove", json!({"memberId": member})).await
        }
        "host" => {
            only(&options, &["title", "ip", "source", "instructions", "authorization", "url", "health"])?;
            let [company] = positionals else {
                return Err(format!("Name the company once, in quotes when it has spaces, such as yougori bounty host \"Example Co\" with the options below.\n{USAGE}"));
            };
            let title = options.values.get("title").ok_or("--title names the bounty, such as \"Review checkout\"")?;
            let address = options.values.get("ip").ok_or("--ip is this computer's LAN or VPN address, which joining computers reach, such as 192.168.1.20")?;
            let url = options.values.get("url");
            let source = options.values.get("source");
            // Source is required for a review, but optional for a live URL (a pure black-box test).
            if source.is_none() && url.is_none() {
                return Err(if crate::distribution::LIVE_TARGETS { "--source is the folder of files to review, or use --url to test a live service with no source" } else { "--source is required: choose the folder of files to review in an isolated sandbox" }.into());
            }
            if url.is_none() && options.values.contains_key("health") {
                return Err("--health describes a live target; add --url to declare one".into());
            }
            if !options.yes {
                return Err("Hosting a closed bounty opens a service on this computer's network address that computers with the password can join. Repeat with --yes only if this is intended.".into());
            }
            // Resolve the source path before prompting for the password, so a bad path fails fast.
            let absolute = match source {
                Some(source) => {
                    let root = Path::new(source);
                    if !root.is_dir() {
                        return Err(format!("--source is a folder of the files to review; {} is not a folder", root.display()));
                    }
                    Some(std::fs::canonicalize(root).map_err(|error| format!("Cannot read {}: {error}", root.display()))?)
                }
                None => None,
            };
            let secret = password(&options)?;
            crate::client::start(None).await?;
            // The engine reads the source from disk on this computer, so a whole repository is hosted
            // without its files crossing the request frame: only the absolute path and the import id
            // travel over the wire. The engine applies the real caps (64 MiB, secret stripping).
            let mut request = json!({"action": "hostSource", "confirmed": true, "name": company, "address": address, "password": secret, "title": title});
            if let Some(absolute) = absolute {
                let imported = call("bounty_dispatch", json!({"request": {"action": "inspectProject", "path": absolute.to_string_lossy()}})).await?;
                request["importId"] = json!(imported["importId"].as_str().ok_or("The project could not be imported for review")?);
            }
            if let Some(instructions) = options.values.get("instructions") {
                request["instructions"] = json!(instructions);
            }
            if let Some(authorization) = options.values.get("authorization") {
                request["authorization"] = json!(authorization);
            }
            // --url makes this a live-target bounty: workers probe the declared running service over
            // the network, reviewing any uploaded source alongside it.
            if let Some(url) = url {
                let mut target = json!({"kind": "url", "baseUrl": url});
                if let Some(health) = options.values.get("health") {
                    target["healthPath"] = json!(health);
                }
                request["target"] = target;
            }
            call("bounty_dispatch", json!({"request": request})).await
        }
        _ => Err(USAGE.into()),
    }
}

/// Terminal text for a hosted bounty and the admin's actions.
pub fn render(value: &Value) -> String {
    if value["deleted"] == true {
        return "Stopped hosting the closed bounty. Computers working it can no longer reach this host.".into();
    }
    if value["removed"] == true {
        return format!("Removed {} from the closed bounty.", value["name"].as_str().unwrap_or("the computer"));
    }
    // `bounty hosted` wraps the view in {host}; `bounty host` returns the view directly.
    let host = if value.get("host").is_some() { &value["host"] } else { value };
    if !host.is_object() {
        return "This computer is not hosting a closed bounty.\nPublish one with:  yougori bounty host COMPANY --title TITLE --ip THIS_PC_IP --source DIR --yes".into();
    }
    let bounty = &host["bounty"];
    let computers = &host["computers"];
    let mut lines = vec![
        format!("Closed Bounty · {} (host)", host["name"].as_str().unwrap_or_default()),
        format!(
            "Source      {} · {} files · {} KB",
            bounty["title"].as_str().unwrap_or_default(),
            bounty["files"].as_u64().unwrap_or(0),
            bounty["bytes"].as_u64().unwrap_or(0) / 1024
        ),
        format!("Address     {}:{}", host["address"].as_str().unwrap_or_default(), host["port"].as_u64().unwrap_or(0)),
        format!("Fingerprint {}", host["fingerprint"].as_str().unwrap_or_default()),
    ];
    if let Some(invite) = host["invite"].as_str() {
        lines.push(format!("Invite      {invite}"));
        lines.push("            Share it with each hunting computer, and the password separately; they paste it, enter the password and choose their own model.".into());
    }
    lines.push(format!(
        "Computers   {} joined · {} online · {} working",
        computers["total"].as_u64().unwrap_or(0),
        computers["online"].as_u64().unwrap_or(0),
        computers["working"].as_u64().unwrap_or(0)
    ));
    for member in host["members"].as_array().into_iter().flatten() {
        lines.push(format!(
            "Computer    {} · {} · {} · {} findings{}",
            member["id"].as_str().unwrap_or_default(),
            member["name"].as_str().unwrap_or_default(),
            member["model"].as_str().unwrap_or("no model yet"),
            member["findings"].as_u64().unwrap_or(0),
            if member["online"] == true { "" } else { " · offline" }
        ));
    }
    // Both kinds of finding are shown: the reports managed workers submit through coordination,
    // and the older findings route, so switching between the CLI and the desktop shows the same.
    let findings = host["findings"].as_array().cloned().unwrap_or_default();
    let reports = host["coordination"]["reports"].as_array().cloned().unwrap_or_default();
    if findings.is_empty() && reports.is_empty() {
        lines.push("Findings    none yet".into());
    }
    for report in reports {
        let who = host["members"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|member| member["id"] == report["memberId"])
            .and_then(|member| member["name"].as_str())
            .unwrap_or_else(|| report["memberId"].as_str().unwrap_or_default())
            .to_owned();
        lines.push(format!(
            "Report      [{}] {} · from {} · {}",
            report["state"].as_str().unwrap_or("submitted"),
            report["title"].as_str().unwrap_or_default(),
            who,
            report["id"].as_str().unwrap_or_default()
        ));
    }
    for finding in findings {
        lines.push(format!(
            "Finding     [{}] {} · from {}",
            finding["severity"].as_str().unwrap_or("?"),
            finding["title"].as_str().unwrap_or_default(),
            finding["memberName"].as_str().unwrap_or_default()
        ));
    }
    lines.push("Remove      yougori bounty remove-hunter MEMBER_ID --yes".into());
    lines.push("Stop        yougori bounty unhost --yes".into());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }
    fn parse(args: &[&str]) -> Result<Options, String> {
        options(&words(args)[1..])
    }

    #[test]
    fn it_owns_only_the_host_verbs() {
        assert!(requested(&words(&["bounty", "host", "Acme"])));
        assert!(requested(&words(&["bounty", "hosted"])) && requested(&words(&["bounty", "unhost"])) && requested(&words(&["bounty", "remove-hunter", "m-1"])));
        assert!(!requested(&words(&["bounty", "status"])) && !requested(&words(&["bounty", "workers"])) && !requested(&words(&["bounty"])));
    }

    #[test]
    fn passwords_in_arguments_and_unknown_options_are_refused() {
        for args in [&["bounty", "host", "Acme", "--password", "hunter2"][..], &["bounty", "host", "Acme", "--password=hunter2"]] {
            assert!(parse(args).unwrap_err().contains("Never type the password"));
        }
        assert!(parse(&["bounty", "host", "Acme", "--colour"]).unwrap_err().contains("Unknown option"));
        assert!(parse(&["bounty", "host", "Acme", "--title"]).unwrap_err().contains("needs a value"));
        assert!(parse(&["bounty", "host", "--title", "a", "--title", "b"]).unwrap_err().contains("twice"));
    }

    #[test]
    fn host_options_read_naturally() {
        let options = parse(&["bounty", "host", "Acme", "--title", "Review checkout", "--ip", "10.0.0.5", "--source", "./src", "--password", "-", "--yes"]).unwrap();
        assert_eq!(options.words.as_slice(), &["host".to_owned(), "Acme".to_owned()]);
        assert_eq!((options.values["title"].as_str(), options.values["ip"].as_str(), options.values["source"].as_str()), ("Review checkout", "10.0.0.5", "./src"));
        assert!(only(&options, &["title", "ip", "source"]).is_ok() && only(&options, &["title"]).is_err());
        assert_eq!((options.password, options.yes), (Some(Some("-".into())), true));
    }

    #[test]
    fn live_target_options_follow_the_compiled_distribution_before_any_engine_request() {
        for flag in ["--url", "--health"] {
            let result = parse(&["bounty", "host", "Example", flag, "https://fixture.invalid"]);
            if crate::distribution::LIVE_TARGETS {
                assert!(result.is_ok());
            } else {
                assert_eq!(result.unwrap_err(), crate::distribution::LIVE_TARGETS_DISABLED);
            }
        }
        assert_eq!(USAGE.contains("--url"), crate::distribution::LIVE_TARGETS);
    }

    #[test]
    fn host_text_covers_the_invite_computers_and_findings() {
        let view = json!({"host": {"name": "Acme", "address": "10.0.0.5", "port": 7462, "fingerprint": "AB:CD",
            "bounty": {"title": "Review checkout", "files": 3, "bytes": 2048},
            "invite": "bounty-invite:xyz",
            "computers": {"total": 2, "online": 1, "working": 1},
            "members": [{"id": "m-1", "name": "Design laptop", "model": "hf.co/acme/model-GGUF", "findings": 1, "online": true}],
            "findings": [{"severity": "high", "title": "Total is not recomputed", "memberName": "Design laptop"}]}});
        let text = render(&view);
        for needle in ["Acme (host)", "Review checkout · 3 files · 2 KB", "10.0.0.5:7462", "bounty-invite:xyz", "Design laptop · hf.co/acme/model-GGUF", "[high] Total is not recomputed · from Design laptop", "yougori bounty unhost --yes"] {
            assert!(text.contains(needle), "{needle} in\n{text}");
        }
        assert!(render(&json!({"host": null})).contains("not hosting a closed bounty"));
        assert!(render(&json!({"deleted": true})).contains("Stopped hosting"));
        assert!(render(&json!({"removed": true, "name": "Design laptop"})).contains("Removed Design laptop"));
    }
}
