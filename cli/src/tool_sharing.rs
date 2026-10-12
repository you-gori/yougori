//! Tool sharing uses the existing authenticated gateway, never a second SSH service.
use crate::public::call;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    io::IsTerminal,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use zeroize::Zeroizing;

pub const HELP: &str = "Yougori shared sandbox\n\n  yougori connect LINK USERNAME [PASSWORD]\n\nOpens the owner's shared sandbox in this terminal, like an SSH session.\nUse the complete HTTPS share link and the credentials supplied by its owner.\nRun the installed tool (codex, claude, opencode, etc.) inside this shell.\nCtrl+] disconnects; the sandbox and files stay on the owner's computer.\nThe owner must keep Yougori, the container and sharing gateway running.\n\nLeave out PASSWORD to type it privately. A password in the command can appear\nin shell history and process arguments. For credentials supplied privately\nthrough JSON, use yougori remote connect --file -.\n";

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
            // PowerShell also ends single-quoted strings at typographic single quotes
            // (U+2018–U+201B); doubling any of them keeps it literal.
            let mut quoted = String::with_capacity(value.len() + 2);
            quoted.push('\'');
            for c in value.chars() {
                if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
                    quoted.push(c);
                }
                quoted.push(c);
            }
            quoted.push('\'');
            quoted
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
    if !(2..=3).contains(&args.len()) {
        return Err("Usage: yougori connect LINK USERNAME [PASSWORD]".into());
    }
    share_address(&args[0])?;
    let name = username(&args[1])?;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("yougori connect requires an interactive terminal. For scripts use yougori remote connect --file -.".into());
    }
    let secret = match args.get(2) {
        Some(secret) => Zeroizing::new(secret.clone()),
        // Typed privately: kept out of shell history and process arguments.
        None => {
            use crate::cli_ui as ui;
            let _raw = ui::Raw::on()?;
            Zeroizing::new(ui::input(&format!("{name} · password"), "", true, &|entry| {
                password(entry)?;
                Ok(entry.into())
            })?)
        }
    };
    password(&secret)?;
    use crate::cli_ui as ui;
    // Spinners show these waits; the engine's progress notes would break their line.
    crate::client::QUIET.store(true, Ordering::Relaxed);
    let connected = async {
        ui::busy("Starting Yougori engine", crate::client::start(None)).await?;
        ui::busy(
            "Connecting to the shared sandbox",
            call(
                "connect_remote_share",
                json!({"link":args[0],"username":name,"password":secret.as_str()}),
            ),
        )
        .await
    }
    .await;
    let state = match connected {
        // Ctrl+C stops waiting; a connection the engine already made stays listed in yougori ps.
        Err(error) if error == ui::CANCELLED => {
            ui::outro(&ui::muted(&error));
            return Ok(());
        }
        result => result?,
    };
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
            // Includes Back, which belongs to the wizard asking this question.
            Err(error) => return Err(error),
        }
    }
}

/// Ends a tool launch quietly from a wizard step: the person cancelled a question or chose a
/// stop action, and the screen already shows which.
pub(crate) const ENDED: &str = "\u{1}yougori launch ended";

/// [`share_prompt`] for a wizard step: Back reaches the wizard untouched, and a cancelled
/// question or a stop action ends the launch with [`ENDED`].
pub(crate) async fn step_prompt<T>(
    id: &str,
    prompt: impl FnMut() -> Result<T, String>,
) -> Result<T, String> {
    share_prompt(id, prompt).await?.ok_or_else(|| ENDED.into())
}

/// Read-only work behind a spinner. Ctrl+C stops waiting and opens the stop menu; Cancel there
/// starts the work again.
pub(crate) async fn step_wait<T, Fut>(
    id: &str,
    label: &str,
    mut work: impl FnMut() -> Fut,
) -> Result<T, String>
where
    Fut: Future<Output = Result<T, String>>,
{
    use crate::cli_ui as ui;
    loop {
        match ui::busy(label, work()).await {
            Err(error) if error == ui::CANCELLED => {
                if crate::sandbox_stop::menu(id).await? {
                    return Err(ENDED.into());
                }
            }
            result => return result,
        }
    }
}

/// Engine work that must not stop half done, such as publishing a link, shown as `label` and
/// then as `done` or `failed`. Keys typed meanwhile are dropped so they cannot answer the next
/// question. Ctrl+C opens the stop menu once the work is done; a second Ctrl+C quits at once.
pub(crate) async fn finish_first<T>(
    id: &str,
    label: &str,
    [done, failed]: [&str; 2],
    work: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    use crate::cli_ui as ui;
    let interrupted = Arc::new(AtomicBool::new(false));
    let result = {
        let _keys = ui::Interrupts::watch(interrupted.clone());
        let task = ui::task(label);
        let mut work = std::pin::pin!(work);
        let mut noted = false;
        let result = loop {
            tokio::select! {
                result = &mut work => break result,
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)), if !noted => {
                    if interrupted.load(Ordering::Relaxed) {
                        noted = true;
                        task.detail("stop options open when this is done");
                    }
                }
            }
        };
        match &result {
            Ok(_) => task.done(done),
            Err(_) => task.fail(failed),
        }
        result
    };
    if result.is_ok()
        && interrupted.load(Ordering::Relaxed)
        && crate::sandbox_stop::menu(id).await?
    {
        return Err(ENDED.into());
    }
    result
}

/// 24 hours, 7 days and 1 hour, in the order the expiry question lists them.
const EXPIRY_SECONDS: [u64; 3] = [86400, 604800, 3600];

fn teammate_count(entry: &str, available: usize) -> Result<String, String> {
    entry
        .parse::<usize>()
        .ok()
        .filter(|n| (1..=available).contains(n))
        .map(|n| n.to_string())
        .ok_or_else(|| format!("Enter a number between 1 and {available}."))
}

#[derive(Debug, PartialEq)]
enum Question {
    Count,
    Username(usize),
    Password(usize),
    Expiry,
    Confirm,
    Done,
}

/// Answers are asked in order, so an answer replaces the one given before going back, or
/// follows the earlier teammates' answers.
fn replace<T>(answers: &mut Vec<T>, index: usize, answer: T) {
    match answers.get_mut(index) {
        Some(previous) => *previous = answer,
        None => answers.push(answer),
    }
}

/// The question a sharing step asks: first the teammate count, then each teammate's username
/// and password, then the expiry and the confirmation.
fn question(step: usize, count: usize) -> Question {
    match step {
        0 => Question::Count,
        n if n <= 2 * count && n % 2 == 1 => Question::Username(n / 2),
        n if n <= 2 * count => Question::Password(n / 2 - 1),
        n if n == 2 * count + 1 => Question::Expiry,
        n if n == 2 * count + 2 => Question::Confirm,
        _ => Question::Done,
    }
}

/// Asks who to add, then creates their access. Each question after the first offers Back;
/// nothing is created until the person confirms.
pub(crate) async fn share(id: &str, name: &str) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let _raw = ui::Raw::on()?;
    ui::intro(
        "Share sandbox",
        &name.chars().filter(|c| !c.is_control()).collect::<String>(),
    );
    let listing = step_wait(id, "Checking teammate access", || {
        call("list_remote_shares", json!({}))
    })
    .await?;
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
    // The draft survives going back, so earlier answers are offered again.
    let mut count = 1;
    let mut names: Vec<String> = vec![];
    let mut secrets: Vec<Zeroizing<String>> = vec![];
    let mut expiry = 0;
    let mut steps = ui::Wizard::new();
    loop {
        let asked: Result<bool, String> = match question(steps.step(), count) {
            Question::Count => async {
                let default = count.to_string();
                let entry = step_prompt(id, || {
                    ui::input("How many teammates?", &default, false, &|entry| {
                        teammate_count(entry, available)
                    })
                })
                .await?;
                count = entry.parse().map_err(|_| "Invalid teammate count")?;
                names.truncate(count);
                secrets.truncate(count);
                Ok(true)
            }
            .await,
            Question::Username(index) => async {
                let previous = names.get(index).cloned().unwrap_or_default();
                let earlier = &names[..index];
                let name = step_prompt(id, || {
                    ui::input(
                        &format!("Teammate {} · username", index + 1),
                        &previous,
                        false,
                        &|entry| {
                            let name = username(entry)?;
                            if earlier.contains(&name) {
                                return Err("Each teammate needs a different username.".into());
                            }
                            Ok(name)
                        },
                    )
                })
                .await?;
                replace(&mut names, index, name);
                Ok(true)
            }
            .await,
            Question::Password(index) => async {
                let label = format!("{} · password", names[index]);
                let secret = Zeroizing::new(
                    step_prompt(id, || {
                        ui::input(&label, "", true, &|entry| {
                            password(entry)?;
                            Ok(entry.into())
                        })
                    })
                    .await?,
                );
                replace(&mut secrets, index, secret);
                Ok(true)
            }
            .await,
            Question::Expiry => async {
                expiry = step_prompt(id, || {
                    ui::select(
                        "Access expires after",
                        &[],
                        &[
                            Choice::new("24 hours", "one day"),
                            Choice::new("7 days", "one week"),
                            Choice::new("1 hour", "short session"),
                        ],
                        expiry,
                    )
                })
                .await?;
                Ok(true)
            }
            .await,
            Question::Confirm => async {
                let notes = vec![
                    format!("{count} teammates · control of this sandbox, its files, tool sign-in and connected access · {} hours", EXPIRY_SECONDS[expiry] / 3600),
                    "Existing active recipients also become reachable when the sharing gateway is enabled.".into(),
                    "Each connection command includes that teammate's password. Send it only to them.".into(),
                ];
                let confirm = step_prompt(id, || {
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
                .await?;
                if confirm != 0 {
                    return Err(ENDED.to_owned());
                }
                Ok(true)
            }
            .await,
            Question::Done => break,
        };
        steps.next(asked)?;
    }
    drop(steps);
    let recipients: Vec<Recipient> = names
        .into_iter()
        .zip(secrets)
        .map(|(username, password)| Recipient { username, password })
        .collect();
    let seconds = EXPIRY_SECONDS[expiry];
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + seconds;
    let links = finish_first(
        id,
        "Creating teammate accounts and sharing links",
        ["Teammate access ready", "Sharing could not finish"],
        create_recipients(id, &recipients, expires, |method, params| {
            call(method, params)
        }),
    )
    .await?;
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
    // The access exists now; going back would create it again.
    let open = step_prompt(id, || {
        ui::without_back(|| {
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
    })
    .await?;
    if open != 0 {
        return Err(ENDED.into());
    }
    Ok(true)
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
        // Typographic single quotes also end PowerShell strings; each is doubled.
        let curly = recipient("alice", "a\u{2018}b\u{2019}c\u{201a}d\u{201b}e; whoami");
        let command = connection_command(LINK, &curly, true).unwrap();
        assert!(command.ends_with("'a\u{2018}\u{2018}b\u{2019}\u{2019}c\u{201a}\u{201a}d\u{201b}\u{201b}e; whoami'"), "{}", command.as_str());
        assert!(password("hello\nworld").is_err());
        assert!(password("short").is_err());
        assert_eq!(username(" Alice ").unwrap(), "alice");
        assert!(username("alice;bad").is_err());
    }
    #[cfg(windows)]
    #[test]
    fn powershell_parses_the_invite_as_literal_arguments() {
        use std::os::windows::process::CommandExt;
        let secret = "literal'\" $(throw 'injection') ; `hello` / → café \u{2019}; throw \u{2018}curly\u{2019}; \u{201b}";
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
    #[tokio::test]
    async fn wizard_steps_receive_back_untouched_and_a_cancelled_question_ends_the_launch() {
        use crate::cli_ui as ui;
        assert_eq!(step_prompt("env", || Ok::<_, String>(3)).await, Ok(3));
        assert_eq!(step_prompt("env", || Err::<usize, _>(ui::BACK.to_owned())).await, Err(ui::BACK.into()));
        // Esc without Back: the question shows it was cancelled, so the launch ends quietly.
        assert_eq!(step_prompt("env", || Err::<usize, _>(ui::CANCELLED.to_owned())).await, Err(ENDED.into()));
        assert_eq!(step_prompt("env", || Err::<usize, _>("broken".to_owned())).await, Err("broken".into()));
    }
    #[test]
    fn sharing_questions_follow_the_teammate_count_and_going_back_keeps_answers() {
        let order: Vec<Question> = (0..8).map(|step| question(step, 2)).collect();
        assert_eq!(order, [
            Question::Count,
            Question::Username(0),
            Question::Password(0),
            Question::Username(1),
            Question::Password(1),
            Question::Expiry,
            Question::Confirm,
            Question::Done,
        ]);
        assert_eq!(question(3, 1), Question::Expiry);
        let mut names = vec!["alice".to_owned(), "bob".to_owned()];
        replace(&mut names, 0, "carol".to_owned());
        assert_eq!(names, ["carol", "bob"], "answering again keeps later teammates");
        replace(&mut names, 2, "dave".to_owned());
        assert_eq!(names, ["carol", "bob", "dave"]);
        assert_eq!(teammate_count("2", 5).unwrap(), "2");
        for entry in ["0", "6", "two", ""] {
            assert!(teammate_count(entry, 5).is_err(), "{entry}");
        }
        assert_eq!(EXPIRY_SECONDS.map(|seconds| seconds / 3600), [24, 168, 1]);
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
