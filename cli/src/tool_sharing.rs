//! Tool sharing uses the existing authenticated gateway, never a second SSH service.
use crate::public::call;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{future::Future, io::IsTerminal};
use zeroize::Zeroizing;

pub const HELP: &str = "Yougori shared sandbox\n\n  yougori connect LINK USERNAME PASSWORD\n\nOpens the owner's shared sandbox in this terminal, like an SSH session.\nUse the complete HTTPS share link and the credentials supplied by its owner.\nRun the installed tool (codex, claude, opencode, etc.) inside this shell.\nCtrl+] disconnects; the sandbox and files stay on the owner's computer.\nThe owner must keep Yougori, the container and sharing gateway running.\n\nPasswords in this command can appear in shell history and process arguments.\nFor credentials supplied privately through JSON, use yougori remote connect --file -.\n";

pub(crate) struct Recipient {
    pub username: String,
    pub password: Zeroizing<String>,
}

pub(crate) fn username(value: &str) -> Result<String, String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(
            "Use 1–64 letters, numbers, dots, underscores or hyphens for the username.".into(),
        );
    }
    Ok(value)
}

pub(crate) fn password(value: &str) -> Result<(), String> {
    if !(8..=256).contains(&value.len()) || value.chars().any(char::is_control) {
        return Err("Use a password between 8 and 256 bytes, without control characters.".into());
    }
    Ok(())
}

fn share_address(link: &str) -> Result<(String, String), String> {
    let url = reqwest::Url::parse(link)
        .map_err(|_| "Use the complete HTTPS share link from its owner")?;
    let id = url
        .path()
        .strip_prefix("/share/")
        .filter(|id| {
            id.starts_with("share-")
                && id.len() == 38
                && id[6..].bytes().all(|b| b.is_ascii_hexdigit())
        })
        .ok_or("Use the complete link ending in /share/share-…")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_some()
        || link.chars().any(char::is_control)
    {
        return Err(
            "Use an HTTPS share link without credentials, query parameters or a custom port".into(),
        );
    }
    Ok((url.origin().ascii_serialization(), id.into()))
}

fn gateway_link(base: &str, id: &str) -> Result<String, String> {
    let link = format!("{}/share/{id}", base.trim_end_matches('/'));
    share_address(&link)?;
    Ok(link)
}

pub(crate) fn connection_command(
    link: &str,
    recipient: &Recipient,
    powershell: bool,
) -> Result<Zeroizing<String>, String> {
    share_address(link)?;
    username(&recipient.username)?;
    password(&recipient.password)?;
    let quote = |value: &str| {
        if powershell {
            format!("'{}'", value.replace('\'', "''"))
        } else {
            shell_words::quote(value).into_owned()
        }
    };
    Ok(Zeroizing::new(format!(
        "yougori connect {} {} {}",
        quote(link),
        quote(&recipient.username),
        quote(&recipient.password)
    )))
}

fn created_ids(created: &[String]) -> String {
    if created.is_empty() {
        "No recipient creation was confirmed.".into()
    } else {
        format!("Recipients already created: {}. Inspect them with yougori remote list; revoke unwanted access with yougori remote revoke ID --yes.", created.join(", "))
    }
}

// Injectable control calls let tests exercise partial failures without exposing a real sandbox.
pub(crate) async fn create_recipients<F, Fut>(
    id: &str,
    recipients: &[Recipient],
    expires_at: u64,
    mut rpc: F,
) -> Result<Vec<String>, String>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    if recipients.is_empty() || recipients.len() > 128 {
        return Err("Choose 1–128 teammates.".into());
    }
    let mut seen = std::collections::HashSet::new();
    for recipient in recipients {
        let name = username(&recipient.username)?;
        if !seen.insert(name) {
            return Err("Each teammate needs a different username.".into());
        }
        password(&recipient.password)?;
    }
    let mut created = Vec::new();
    for recipient in recipients {
        let result = rpc("create_remote_share", json!({"request":{
            "targetId":id,"username":recipient.username,"password":recipient.password.as_str(),
            "permission":"control","folder":null,"expiresAt":expires_at,"acknowledgeExistingAccess":true
        }})).await.map_err(|error| format!("Recipient creation stopped: {error}. {} A failed call may have completed; inspect sharing before retrying.", created_ids(&created)))?;
        let share_id = result["id"]
            .as_str()
            .filter(|id| {
                id.starts_with("share-")
                    && id.len() == 38
                    && id[6..].bytes().all(|b| b.is_ascii_hexdigit())
            })
            .ok_or_else(|| {
                format!(
                    "Sharing returned an invalid recipient ID. {} Inspect sharing before retrying.",
                    created_ids(&created)
                )
            })?;
        created.push(share_id.to_owned());
    }
    let tunnel = rpc("start_remote_tunnel", json!({})).await
        .map_err(|error| format!("The recipients were created, but the gateway could not start: {error}. {} Retry only the gateway with yougori remote start --yes.", created_ids(&created)))?;
    let base = tunnel["url"]
        .as_str()
        .ok_or_else(|| format!("The gateway returned no address. {}", created_ids(&created)))?;
    created
        .iter()
        .map(|share_id| {
            gateway_link(base, share_id)
                .map_err(|error| format!("{error}. {}", created_ids(&created)))
        })
        .collect()
}

fn connected_environment<'a>(state: &'a Value, link: &str) -> Result<&'a str, String> {
    let (base, share_id) = share_address(link)?;
    let runtime = format!(
        "shared://tunnel/{:x}/{share_id}",
        Sha256::digest(base.as_bytes())
    );
    let mut matches = state["environments"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|env| env["runtime"] == runtime);
    let environment = matches.next().ok_or(
        "Connected, but the shared sandbox was not returned. Run yougori ps --type shared.",
    )?;
    if matches.next().is_some() {
        return Err("More than one node matches this share. Run yougori ps --type shared.".into());
    }
    environment["id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "The shared sandbox returned no ID".into())
}

pub async fn connect(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err("Usage: yougori connect LINK USERNAME PASSWORD".into());
    }
    share_address(&args[0])?;
    let name = username(&args[1])?;
    let secret = Zeroizing::new(args[2].clone());
    password(&secret)?;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("yougori connect requires an interactive terminal. For scripts use yougori remote connect --file -.".into());
    }
    crate::client::start(None).await?;
    let state = call(
        "connect_remote_share",
        json!({"link":args[0],"username":name,"password":secret.as_str()}),
    )
    .await?;
    drop(secret);
    let id = connected_environment(&state, &args[0])?;
    // Permission checks stay in the gateway; do not start or install on the owner's behalf.
    crate::terminal::attach(id, Some(&crate::terminal::shared_tool_shell())).await
}

pub(crate) async fn share_prompt<T>(
    id: &str,
    mut prompt: impl FnMut() -> Result<T, String>,
) -> Result<Option<T>, String> {
    use crate::cli_ui as ui;
    loop {
        ui::take_interrupt();
        match prompt() {
            Ok(value) => return Ok(Some(value)),
            Err(error) if error == ui::CANCELLED => {
                if ui::take_interrupt() {
                    if crate::sandbox_stop::menu(id).await? {
                        return Ok(None);
                    }
                    // Cancel in the stop menu returns to this step, retaining
                    // every teammate already entered in the current draft.
                } else {
                    return Ok(None);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) async fn share(id: &str, name: &str) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let _raw = ui::Raw::on()?;
    ui::intro(
        "Share sandbox",
        &name.chars().filter(|c| !c.is_control()).collect::<String>(),
    );
    let listing = call("list_remote_shares", json!({})).await?;
    let active = listing["grants"]
        .as_array()
        .ok_or("Sharing returned no recipient list")?
        .iter()
        .filter(|grant| matches!(grant["status"].as_str(), Some("online" | "offline")))
        .count();
    let available = 128usize.saturating_sub(active);
    if available == 0 {
        return Err("The maximum of 128 recipients has been reached. Revoke unused recipients with yougori remote revoke ID --yes.".into());
    }
    let Some(count) = share_prompt(id, || {
        ui::input("How many teammates?", "1", false, &|entry| {
            entry
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=available).contains(n))
                .map(|n| n.to_string())
                .ok_or_else(|| format!("Enter a number between 1 and {available}."))
        })
    })
    .await?
    else {
        return Ok(false);
    };
    let count = count
        .parse::<usize>()
        .map_err(|_| "Invalid teammate count")?;
    let mut recipients: Vec<Recipient> = vec![];
    for index in 0..count {
        let Some(name) = share_prompt(id, || {
            ui::input(
                &format!("Teammate {} · username", index + 1),
                "",
                false,
                &|entry| {
                    let name = username(entry)?;
                    if recipients.iter().any(|person| person.username == name) {
                        return Err("Each teammate needs a different username.".into());
                    }
                    Ok(name)
                },
            )
        })
        .await?
        else {
            return Ok(false);
        };
        let Some(secret) = share_prompt(id, || {
            ui::input(&format!("{name} · password"), "", true, &|entry| {
                password(entry)?;
                Ok(entry.into())
            })
        })
        .await?
        else {
            return Ok(false);
        };
        recipients.push(Recipient {
            username: name,
            password: Zeroizing::new(secret),
        });
    }
    let Some(expiry) = share_prompt(id, || {
        ui::select(
            "Access expires after",
            &[],
            &[
                Choice::new("24 hours", "one day"),
                Choice::new("7 days", "one week"),
                Choice::new("1 hour", "short session"),
            ],
            0,
        )
    })
    .await?
    else {
        return Ok(false);
    };
    let seconds = [86400u64, 604800, 3600][expiry];
    let notes = vec![
        format!("{count} teammates · control of this sandbox, its files, tool sign-in and connected access · {} hours", seconds / 3600),
        "Existing active recipients also become reachable when the sharing gateway is enabled.".into(),
        "Each connection command includes that teammate's password. Send it only to them.".into(),
    ];
    let Some(confirm) = share_prompt(id, || {
        ui::select(
            "Create teammate access?",
            &notes,
            &[
                Choice::new(
                    "Create links and connection commands",
                    "enable password-protected sharing",
                ),
                Choice::new("Cancel", "keep the sandbox without adding teammates"),
            ],
            0,
        )
    })
    .await?
    else {
        return Ok(false);
    };
    if confirm != 0 {
        return Ok(false);
    }
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + seconds;
    let task = ui::task("Creating teammate accounts and sharing links");
    let links = match create_recipients(id, &recipients, expires, |method, params| {
        call(method, params)
    })
    .await
    {
        Ok(links) => {
            task.done("Teammate access ready");
            links
        }
        Err(error) => {
            task.fail("Sharing could not finish");
            return Err(error);
        }
    };
    for (person, link) in recipients.iter().zip(&links) {
        ui::step(&format!("{} · {link}", person.username));
        for (label, powershell) in [("PowerShell 7", true), ("macOS / Linux", false)] {
            ui::info(label);
            let command = connection_command(link, person, powershell)?;
            // The normal line painter can transliterate Unicode. Literal invite
            // bytes must stay intact, including passwords and quote characters.
            ui::write(format!("  {}\r\n", command.as_str()).as_bytes());
        }
    }
    ui::info("Teammates open a shell in this sandbox, then run the installed tool. Keep the owner computer, sandbox and gateway running.");
    let Some(open) = share_prompt(id, || {
        ui::select(
            "Connection commands are ready to copy",
            &[],
            &[
                Choice::new("Open tool", "continue in this terminal"),
                Choice::new("Leave shared", "return to your PC terminal"),
            ],
            0,
        )
    })
    .await?
    else {
        return Ok(false);
    };
    Ok(open == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    const LINK: &str = "https://example.com/share/share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fn recipient(name: &str, secret: &str) -> Recipient {
        Recipient {
            username: name.into(),
            password: Zeroizing::new(secret.into()),
        }
    }
    #[test]
    fn command_quotes_passwords_without_changing_or_executing_them() {
        let secret = "quote'\" $() ; `hello` / space → café";
        let person = recipient("alice", secret);
        let command = connection_command(LINK, &person, false).unwrap();
        assert_eq!(
            shell_words::split(&command).unwrap(),
            ["yougori", "connect", LINK, "alice", secret]
        );
        let command = connection_command(LINK, &person, true).unwrap();
        assert!(command.contains("quote''\" $() ; `hello` / space → café"));
        assert!(!command.contains("'\"'\"'"));
        assert!(password("hello\nworld").is_err());
        assert!(password("short").is_err());
        assert_eq!(username(" Alice ").unwrap(), "alice");
        assert!(username("alice;bad").is_err());
    }
    #[cfg(windows)]
    #[test]
    fn powershell_parses_the_invite_as_literal_arguments() {
        use std::os::windows::process::CommandExt;
        let secret = "literal'\" $(throw 'injection') ; `hello` / → café";
        let person = recipient("alice", secret);
        let invite = connection_command(LINK, &person, true).unwrap();
        let script = format!("[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); function yougori {{ ConvertTo-Json -InputObject @($args) -Compress }}; {}", invite.as_str());
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            json!(["connect", LINK, "alice", secret])
        );
    }
    #[test]
    fn connection_selects_the_requested_share_even_when_old_nodes_exist() {
        let runtime = format!(
            "shared://tunnel/{:x}/share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Sha256::digest(b"https://example.com")
        );
        let state = json!({"environments":[{"id":"local","runtime":"ubuntu"},{"id":"old","runtime":"shared://other"},{"id":"correct","runtime":runtime}]});
        assert_eq!(connected_environment(&state, LINK).unwrap(), "correct");
        for link in [
            "http://example.com/share/share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://user:pw@example.com/share/share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://example.com/share/share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?pw=secret",
            "https://example.com/share/bad",
        ] {
            assert!(share_address(link).is_err());
        }
    }
    #[tokio::test]
    async fn multiple_teammates_have_individual_grants_and_one_gateway() {
        let people = [
            recipient("alice", "first password"),
            recipient("bob", "second password"),
        ];
        let mut calls = vec![];
        let links = create_recipients("env-codex", &people, 2000000000, |method, params| {
            calls.push((method, params));
            let value = match calls.len() {
                1 => json!({"id":"share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}),
                2 => json!({"id":"share-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}),
                _ => json!({"url":"https://example.com"}),
            };
            std::future::ready(Ok(value))
        })
        .await
        .unwrap();
        assert_eq!(links[0], LINK);
        assert!(links[1].ends_with("share-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        assert_eq!(
            calls.iter().map(|c| c.0).collect::<Vec<_>>(),
            [
                "create_remote_share",
                "create_remote_share",
                "start_remote_tunnel"
            ]
        );
        for (index, person) in people.iter().enumerate() {
            let request = &calls[index].1["request"];
            assert_eq!(request["targetId"], "env-codex");
            assert_eq!(request["username"], person.username);
            assert_eq!(request["password"], person.password.as_str());
            assert_eq!(request["permission"], "control");
            assert_eq!(request["acknowledgeExistingAccess"], true);
            assert_eq!(request["expiresAt"], 2000000000u64);
        }
    }
    #[tokio::test]
    async fn partial_failure_reports_completed_grants_without_retrying_or_starting_gateway() {
        let people = [
            recipient("alice", "first password"),
            recipient("bob", "second password"),
        ];
        let mut count = 0;
        let error = create_recipients("env-codex", &people, 2000000000, |method, _| {
            assert_eq!(method, "create_remote_share");
            count += 1;
            std::future::ready(if count == 1 {
                Ok(json!({"id":"share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}))
            } else {
                Err("request timed out".into())
            })
        })
        .await
        .unwrap_err();
        assert_eq!(count, 2);
        assert!(error.contains("share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(error.contains("may have completed"));
        assert!(!error.contains("password"));
        let error = create_recipients(
            "env-codex",
            &[
                recipient("alice", "first password"),
                recipient("Alice", "second password"),
            ],
            2000000000,
            |_, _| {
                panic!("Invalid input must fail before RPC");
                #[allow(unreachable_code)]
                std::future::ready(Ok(Value::Null))
            },
        )
        .await
        .unwrap_err();
        assert!(error.contains("different username"));
    }
    #[tokio::test]
    async fn gateway_failure_preserves_created_ids_and_never_recreates_accounts() {
        let mut methods = vec![];
        let error = create_recipients(
            "env-codex",
            &[recipient("alice", "first password")],
            2000000000,
            |method, _| {
                methods.push(method);
                std::future::ready(if method == "create_remote_share" {
                    Ok(json!({"id":"share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}))
                } else {
                    Err("tunnel unavailable".into())
                })
            },
        )
        .await
        .unwrap_err();
        assert_eq!(methods, ["create_remote_share", "start_remote_tunnel"]);
        assert!(error.contains("share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(error.contains("Retry only the gateway"));
        assert!(!error.contains("first password"));
    }
    #[test]
    fn recipient_shell_loads_the_shared_tools_without_installing_or_starting_a_new_container() {
        let command = crate::terminal::shared_tool_shell();
        assert!(command.contains("$HOME/.local/share/yougori/bin:$HOME/.local/bin:$PATH"));
        assert!(command.contains("tool-env.sh"));
        assert!(command.contains("cd /workspace"));
        assert!(command.contains("exec /bin/bash -i"));
        assert!(!command.contains("install"));
    }
}
