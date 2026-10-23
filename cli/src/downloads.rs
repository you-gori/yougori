//! A foreground lease keeps downloads tied to the CLI that created the link.
use crate::{client, public::call, wire::Response};
use serde_json::json;
use std::{io::{IsTerminal, Write}, time::{Duration, SystemTime, UNIX_EPOCH}};

fn options(args: &[String]) -> Result<(&str, Option<&str>, bool), String> {
    let environment = args.first().filter(|value| !value.starts_with('-')).ok_or("Usage: yougori download on ENV [--domain HOST] --yes [--dry-run]")?;
    let mut domain = None; let mut yes = false; let mut dry = false; let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--domain" if domain.is_none() => { i += 1; domain = Some(args.get(i).ok_or("--domain requires a saved hostname")?.as_str()); }
            "--yes" if !yes => yes = true,
            "--dry-run" if !dry => dry = true,
            _ => return Err("Usage: yougori download on ENV [--domain HOST] --yes [--dry-run]".into()),
        }
        i += 1;
    }
    if !yes && !dry { return Err("Anyone with the download link can copy every file and credential inside this environment. Add --yes to publish it.".into()); }
    Ok((environment, domain, dry))
}

fn owner() -> String {
    use sha2::{Digest, Sha256};
    let bytes = Sha256::digest(format!("{}-{:?}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()));
    let text: String = bytes[..16].iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &text[..8], &text[8..12], &text[12..16], &text[16..20], &text[20..32])
}

pub async fn run(args: &[String]) -> Result<(), String> {
    let (environment, domain, dry) = options(args)?;
    if dry { println!("{}", machine_output(json!({"dryRun":true,"environment":environment,"domain":domain,"foreground":true}))); return Ok(()); }
    client::start(None).await?;
    let state = call("get_platform_state", json!({})).await?;
    let matches: Vec<_> = state["environments"].as_array().ok_or("Invalid environment list")?.iter()
        .filter(|item| item["id"] == environment || item["name"].as_str().is_some_and(|name| name.eq_ignore_ascii_case(&environment))).collect();
    if matches.len() != 1 { return Err(format!("Environment {environment} was not found, or more than one matches. See your environments with yougori ps.")); }
    let id = matches[0]["id"].as_str().ok_or("Missing environment ID")?;
    if matches[0]["status"] != "stopped" { return Err("Stop this environment before creating its consistent download copy. Run `yougori stop ENV`.".into()); }
    let owner = owner();
    let result = call("start_environment_download", json!({"request":{"environmentId":id,"ownerId":owner,"processId":std::process::id(),"domain":domain}})).await?;
    let terminal = std::io::stdout().is_terminal();
    if terminal {
        println!("Download link: {}\nDownloads (all time): {}\nKeep this CLI open. Ctrl+C turns this link off; the environment stays stopped.", result["url"].as_str().unwrap_or(""), result["downloads"]);
    } else { println!("{}", machine_output(result.clone())); }
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    // Use the same cancellation path on Unix and Windows. A killed process is
    // also detected by the engine's process identity and bounded lease.
    let signal = tokio::signal::ctrl_c(); tokio::pin!(signal);
    let mut interval = tokio::time::interval(Duration::from_secs(20));
    let mut last_count = result["downloads"].as_u64().unwrap_or(0);
    let outcome = loop {
        tokio::select! {
            result = &mut signal => break result.map_err(|e| e.to_string()),
            _ = interval.tick() => {
                let links = match call("keep_environment_downloads_alive", json!({"ownerId":owner})).await {
                    Ok(links) => links,
                    Err(error) => break Err(error),
                };
                let active = links.as_array().and_then(|links| links.iter().find(|link| link["environmentId"] == id));
                if !active.is_some_and(|link| link["active"] == true) { break Ok(()); }
                let count = active.and_then(|link| link["downloads"].as_u64()).unwrap_or(last_count);
                if terminal && count != last_count { println!("Downloads (all time): {count}"); }
                last_count = count;
            }
        }
    };
    let stopped = call("stop_environment_download", json!({"environmentId":id})).await;
    if terminal { println!("Download link off."); }
    outcome?; stopped?; Ok(())
}

fn machine_output(result: serde_json::Value) -> String {
    serde_json::to_string(&Response::success(result)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn download_publication_requires_explicit_confirmation_and_remains_foreground() {
        let args = |values: &[&str]| values.iter().map(|value| value.to_string()).collect::<Vec<_>>();
        assert!(options(&args(&["env-one"])).unwrap_err().contains("--yes"));
        assert!(options(&args(&["env-one", "--yes", "--detach"])).is_err());
        assert!(options(&args(&["env-one", "--yes", "--domain"])).is_err());
        assert!(options(&args(&["env-one", "--dry-run"])).unwrap().2);
        let input = args(&["env-one", "--domain", "copies.example.com", "--yes"]);
        assert_eq!(options(&input).unwrap(), ("env-one", Some("copies.example.com"), false));
    }
    #[test]
    fn owner_is_unique_and_a_valid_uuid_shape() {
        let one = owner(); let two = owner(); assert_ne!(one, two);
        assert_eq!(one.len(), 36);
        assert_eq!(one.chars().filter(|&c| c == '-').count(), 4);
    }
    #[test]
    fn download_results_use_the_versioned_machine_contract() {
        let result = json!({"url":"https://copies.example.com","downloads":4});
        let output: serde_json::Value = serde_json::from_str(&machine_output(result.clone())).unwrap();
        assert_eq!(output["version"], crate::wire::VERSION);
        assert_eq!(output["ok"], true);
        assert_eq!(output["result"], result);
    }
}
