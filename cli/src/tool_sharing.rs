//! Tool sharing uses the existing authenticated gateway, never a second SSH service.
use crate::public::call;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    future::Future,
    io::IsTerminal,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use zeroize::Zeroizing;

pub const HELP: &str = "Yougori shared sandbox\n\n  yougori connect LINK USERNAME [PASSWORD]\n\nOpens the owner's shared sandbox in this terminal, like an SSH session.\nUse the complete HTTPS share link and the credentials supplied by its owner.\nRun the installed tool (codex, claude, opencode, etc.) inside this shell.\nCtrl+] disconnects; the sandbox and files stay on the owner's computer.\nThe owner must keep Yougori, the sandbox and the sharing gateway running.\n\nLeave out PASSWORD to type it privately. A password in the command can appear\nin shell history and process arguments. For credentials supplied privately\nthrough JSON, use yougori remote connect --file -.\n";

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

/// What new recipients may do: view or edit one folder, or control the whole sandbox.
pub(crate) struct Access<'a> {
    pub permission: &'a str,
    pub folder: Option<&'a str>,
}

impl Access<'_> {
    /// Control of the sandbox, its files, tool sign-in and the access already connected to it.
    pub(crate) const CONTROL: Access<'static> = Access { permission: "control", folder: None };
}

/// A recipient's ID, when the value carries a well-formed one.
fn share_id(value: &Value) -> Option<&str> {
    value["id"].as_str().filter(|id| {
        id.starts_with("share-") && id.len() == 38 && id[6..].bytes().all(|b| b.is_ascii_hexdigit())
    })
}

/// People named in a sentence: "alice", "alice and bob", "alice, bob and carol".
fn names<'a>(people: impl IntoIterator<Item = &'a str>) -> String {
    let people: Vec<&str> = people.into_iter().collect();
    match people.as_slice() {
        [] => "nobody".into(),
        [one] => (*one).into(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The access a failed attempt made, and the access of it that could not be taken back.
struct TakenBack {
    made: Vec<String>,
    left: Vec<(String, String)>,
}

impl TakenBack {
    /// What the person reads: what went wrong, then that nothing is shared, or who still has
    /// access and the command that takes it away.
    fn sentence(&self, failure: &str) -> String {
        if self.left.is_empty() {
            return if self.made.is_empty() {
                format!("{failure}. Nothing was shared.")
            } else {
                format!("{failure}. The access just created for {} was taken back, so nothing is shared.", names(self.made.iter().map(String::as_str)))
            };
        }
        let people = names(self.left.iter().map(|(name, _)| name.as_str()));
        let commands = self.left.iter().map(|(_, share)| format!("yougori remote revoke {share} --yes")).collect::<Vec<_>>().join(", then ");
        format!("{failure}. {people} still {} access; take it away with {commands}.", if self.left.len() == 1 { "has" } else { "have" })
    }
}

/// Takes back the access a failed attempt made: the recipients it was told about, and any other
/// active one for this sandbox under one of its usernames that was not there before, since a call
/// that failed may still have finished in the engine. Removing forgets an access entirely; where
/// that fails, revoking still takes it away.
async fn take_back<F, Fut>(
    id: &str,
    recipients: &[Recipient],
    created: &[(String, String)],
    existing: &HashSet<String>,
    rpc: &mut F,
) -> TakenBack
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    let wanted: HashSet<String> = recipients.iter().filter_map(|recipient| username(&recipient.username).ok()).collect();
    let mut made = created.to_vec();
    if let Ok(listing) = rpc("list_remote_shares", json!({})).await {
        for grant in listing["grants"].as_array().into_iter().flatten() {
            let (Some(share), Some(name)) = (share_id(grant), grant["username"].as_str()) else {
                continue;
            };
            if grant["targetId"] == id
                && wanted.contains(name)
                && !existing.contains(share)
                && matches!(grant["status"].as_str(), Some("online" | "offline"))
                && !made.iter().any(|(known, _)| known == share)
            {
                made.push((share.to_owned(), name.to_owned()));
            }
        }
    }
    let mut taken = TakenBack { made: Vec::new(), left: Vec::new() };
    for (share, name) in made {
        if rpc("remove_remote_share", json!({"shareId":share})).await.is_ok()
            || rpc("update_remote_share", json!({"shareId":share,"revoke":true})).await.is_ok()
        {
            taken.made.push(name);
        } else {
            taken.left.push((name, share));
        }
    }
    taken
}

/// Gives each recipient access, turns on the sharing gateway and returns their links. When any
/// step fails, the access this attempt made is taken back again, so a failure never leaves
/// anyone with access the person was not given a link for. `existing` holds every recipient that
/// was there before; those are never touched. Injectable control calls let tests exercise
/// partial failures without exposing a real sandbox.
pub(crate) async fn create_recipients<F, Fut>(
    id: &str,
    recipients: &[Recipient],
    access: &Access<'_>,
    expires_at: u64,
    existing: &HashSet<String>,
    mut rpc: F,
) -> Result<Vec<String>, String>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    if recipients.is_empty() || recipients.len() > 128 {
        return Err("Choose 1–128 teammates.".into());
    }
    let mut seen = HashSet::new();
    for recipient in recipients {
        let name = username(&recipient.username)?;
        if !seen.insert(name) {
            return Err("Each teammate needs a different username.".into());
        }
        password(&recipient.password)?;
    }
    let mut created: Vec<(String, String)> = Vec::new();
    let failure = 'create: {
        for recipient in recipients {
            let result = match rpc("create_remote_share", json!({"request":{
                "targetId":id,"username":recipient.username,"password":recipient.password.as_str(),
                "permission":access.permission,"folder":access.folder,"expiresAt":expires_at,
                "acknowledgeExistingAccess":access.permission == "control"
            }})).await {
                Ok(result) => result,
                Err(error) => break 'create format!("Adding {} did not finish ({error})", recipient.username),
            };
            let Some(share) = share_id(&result) else {
                break 'create format!("Sharing gave an unexpected answer for {}", recipient.username);
            };
            created.push((share.to_owned(), recipient.username.clone()));
        }
        let tunnel = match rpc("start_remote_tunnel", json!({})).await {
            Ok(tunnel) => tunnel,
            Err(error) => break 'create format!("The sharing gateway could not start ({error})"),
        };
        let Some(base) = tunnel["url"].as_str() else {
            break 'create "The sharing gateway did not say where it can be reached".to_owned();
        };
        match created.iter().map(|(share, _)| gateway_link(base, share)).collect::<Result<Vec<_>, _>>() {
            Ok(links) => return Ok(links),
            Err(error) => break 'create format!("The sharing gateway gave an unusable address ({error})"),
        }
    };
    let taken = take_back(id, recipients, &created, existing, &mut rpc).await;
    Err(taken.sentence(&failure))
}

/// The runtime a share link's node is saved under on this computer.
fn shared_runtime(link: &str) -> Result<String, String> {
    let (base, share_id) = share_address(link)?;
    Ok(format!(
        "shared://tunnel/{:x}/{share_id}",
        Sha256::digest(base.as_bytes())
    ))
}

fn connected_environment<'a>(state: &'a Value, link: &str) -> Result<&'a str, String> {
    let runtime = shared_runtime(link)?;
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
            let typed = ui::input(&format!("{name} · password"), "", true, &|entry| {
                password(entry)?;
                Ok(entry.into())
            });
            match typed {
                // Nothing has started yet, so there is nothing to check afterwards.
                Err(error) if error == ui::CANCELLED => {
                    ui::outro(&ui::muted("Cancelled. Nothing was connected."));
                    return Err(crate::wire::cancelled(""));
                }
                typed => Zeroizing::new(typed?),
            }
        }
    };
    password(&secret)?;
    use crate::cli_ui as ui;
    // Spinners show these waits; the engine's progress notes would break their line.
    crate::client::QUIET.store(true, Ordering::Relaxed);
    let before = async {
        ui::busy("Starting Yougori engine", crate::client::start(None)).await?;
        ui::busy("Checking your shared sandboxes", call("get_platform_state", json!({}))).await
    }
    .await;
    let before = match before {
        Err(error) if error == ui::CANCELLED => {
            ui::outro(&ui::muted("Cancelled. Nothing was connected."));
            return Err(crate::wire::cancelled(""));
        }
        result => result?,
    };
    // A cancel removes only a node this connection added; anything listed before stays, and
    // when the list could not be read, nothing is removed.
    let listed = environment_ids(&before);
    let connected = create_or_undo(
        "Connecting to the shared sandbox",
        &Cleanup {
            waiting: "Cancelling · waiting for the connection to finish",
            notice: "The connection is closed again as soon as it finishes. If you quit now, it may stay in yougori ps as a shared sandbox; remove it there with yougori rm NAME --yes.",
            removing: "Closing the connection",
        },
        call(
            "connect_remote_share",
            json!({"link":args[0],"username":name,"password":secret.as_str()}),
        ),
        |made| disconnect_cancelled(&args[0], listed.as_ref(), made, |method, params| call(method, params)),
    )
    .await;
    // A cancelled connection already says what became of it, and ends as a cancellation.
    let state = connected?;
    drop(secret);
    let id = connected_environment(&state, &args[0])?;
    // Permission checks stay in the gateway; do not start or install on the owner's behalf.
    crate::terminal::attach(id, Some(&crate::terminal::shared_tool_shell())).await
}

/// Every environment ID in a platform state, or `None` when the state does not list them. An
/// answer without `environments` is not an empty list: taken as one, everything there would
/// look new, and a cancel could remove something that existed before it.
pub(crate) fn environment_ids(state: &Value) -> Option<HashSet<String>> {
    Some(state["environments"].as_array()?.iter().filter_map(|env| env["id"].as_str()).map(str::to_owned).collect())
}

/// Which environment a cancelled request made, told apart from everything else.
#[derive(Debug, PartialEq)]
pub(crate) enum Made<'a> {
    /// Exactly this one, which did not exist before the request.
    One(&'a str),
    /// No new environment matches: nothing was made, or not yet.
    Nothing,
    /// The request answered with an environment that existed before it; that is never removed.
    Before,
    /// More than one new environment matches, so none of them can be told to be this request's.
    Unclear,
}

/// The environment a cancelled request made, if exactly one can be told apart: the ID the engine
/// returned for it, or else the one new environment that `matches`. An environment whose ID was
/// in `before`, taken just before the request, is never chosen.
pub(crate) fn made_by_request<'a>(
    environments: &'a [Value],
    before: &HashSet<String>,
    returned: Option<&str>,
    matches: impl Fn(&Value) -> bool,
) -> Made<'a> {
    let new = |env: &&'a Value| env["id"].as_str().is_some_and(|id| !id.is_empty() && !before.contains(id));
    if let Some(returned) = returned {
        if before.contains(returned) {
            return Made::Before;
        }
        return match environments.iter().filter(new).find(|env| env["id"] == returned) {
            Some(env) => env["id"].as_str().map_or(Made::Nothing, Made::One),
            None => Made::Nothing,
        };
    }
    let mut found = environments.iter().filter(new).filter(|env| matches(env));
    match (found.next(), found.next()) {
        (None, _) => Made::Nothing,
        (Some(env), None) => env["id"].as_str().map_or(Made::Nothing, Made::One),
        (Some(_), Some(_)) => Made::Unclear,
    }
}

/// Removes the shared sandbox a cancelled connection added, and only that one: a node listed
/// before keeps its place, and when it is not certain which node is new, nothing is removed.
async fn disconnect_cancelled<F, Fut>(
    link: &str,
    listed: Option<&HashSet<String>>,
    made: Option<Value>,
    mut rpc: F,
) -> Result<String, String>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    let by_hand = "Look for it with yougori ps --type shared and remove it with: yougori rm NAME --yes";
    // Without the list from before, nothing this connection made can be told apart.
    let Some(listed) = listed else {
        return Err(format!("Cancelled. Nothing was removed, because Yougori could not tell which shared sandboxes were there before. {by_hand}"));
    };
    let runtime = shared_runtime(link)?;
    let state = rpc("get_platform_state", json!({}))
        .await
        .map_err(|error| format!("Cancelled, but the connection could not be checked ({error}). {by_hand}"))?;
    // An answer that does not list them says nothing about what was connected.
    let Some(environments) = state["environments"].as_array().map(Vec::as_slice) else {
        return Err(format!("Cancelled, but the connection could not be checked: Yougori's answer did not list your sandboxes. {by_hand}"));
    };
    let returned = made.as_ref().and_then(|connected| connected_environment(connected, link).ok());
    let id = match made_by_request(environments, listed, returned, |env| env["runtime"] == runtime.as_str()) {
        Made::One(id) => id,
        Made::Nothing => return Ok("Cancelled. Nothing was connected.".into()),
        Made::Before => return Ok("Cancelled. The shared sandbox stays in your list, as before.".into()),
        Made::Unclear => return Err(format!("Cancelled. Nothing was removed, because it is not certain which connection this was. {by_hand}")),
    };
    let handle = crate::container_tools::handle(environments, id);
    rpc("delete_environment", json!({"environmentId":id}))
        .await
        .map(|_| "Cancelled. The connection was closed again.".to_owned())
        .map_err(|error| format!("Cancelled, but the shared sandbox is still connected ({error}). Remove it with: yougori rm {} --yes", shell_words::quote(&handle)))
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

/// Engine work that must not stop half done, such as creating access, shown as `label` and then
/// as `done` or `failed`. Keys typed meanwhile are dropped so they cannot answer the next
/// question; Ctrl+C is noted (`then` says what follows it) and a second Ctrl+C quits at once.
/// Also returns whether Ctrl+C was pressed.
pub(crate) async fn uninterrupted<T>(
    label: &str,
    [done, failed]: [&str; 2],
    then: &str,
    work: impl Future<Output = Result<T, String>>,
) -> (Result<T, String>, bool) {
    use crate::cli_ui as ui;
    let interrupted = Arc::new(AtomicBool::new(false));
    let _keys = ui::Interrupts::watch(interrupted.clone());
    let task = ui::task(label);
    let mut work = std::pin::pin!(work);
    let mut noted = false;
    let result = loop {
        tokio::select! {
            result = &mut work => break result,
            _ = tokio::time::sleep(Duration::from_millis(50)), if !noted => {
                if interrupted.load(Ordering::Relaxed) {
                    noted = true;
                    task.detail(then);
                }
            }
        }
    };
    match &result {
        Ok(_) => task.done(done),
        Err(_) => task.fail(failed),
    }
    (result, interrupted.load(Ordering::Relaxed))
}

/// [`uninterrupted`] in a sandbox: Ctrl+C opens the stop menu once the work is done.
pub(crate) async fn finish_first<T>(
    id: &str,
    label: &str,
    outcomes: [&str; 2],
    work: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let (result, interrupted) = uninterrupted(label, outcomes, "stop options open when this is done", work).await;
    if result.is_ok() && interrupted && crate::sandbox_stop::menu(id).await? {
        return Err(ENDED.into());
    }
    result
}

/// What a cancelled [`create_or_undo`] shows while it cleans up.
pub(crate) struct Cleanup<'a> {
    /// The spinner once Ctrl+C was pressed, while the engine finishes.
    pub waiting: &'a str,
    /// Said at once on Ctrl+C: what is removed, and how to remove it if the person quits now.
    pub notice: &'a str,
    /// The spinner while what was made is removed.
    pub removing: &'a str,
}

/// Engine work that makes something, such as a sandbox, behind a spinner. Ctrl+C cannot take
/// back a request the engine already has, so the work is allowed to finish and `undo` then
/// removes what it made, given the work's answer when it gave one, and returns what the person
/// reads, or what is left and how to remove it. `undo` removes only what it can tell this request
/// made (see [`made_by_request`]). The notice comes first, so even a second Ctrl+C, which quits
/// at once, leaves the person knowing what may remain. A cancelled run ends as a cancellation
/// ([`crate::wire::cancelled`]) with nothing more to say: the screen already says how.
pub(crate) async fn create_or_undo<T, Fut>(
    label: &str,
    cleanup: &Cleanup<'_>,
    work: impl Future<Output = Result<T, String>>,
    undo: impl FnOnce(Option<T>) -> Fut,
) -> Result<T, String>
where
    Fut: Future<Output = Result<String, String>>,
{
    let cancelled = Arc::new(AtomicBool::new(false));
    let _keys = crate::cli_ui::Interrupts::watch(cancelled.clone());
    finish_or_undo(&cancelled, label, cleanup, work, undo).await
}

async fn finish_or_undo<T, Fut>(
    cancelled: &AtomicBool,
    label: &str,
    cleanup: &Cleanup<'_>,
    work: impl Future<Output = Result<T, String>>,
    undo: impl FnOnce(Option<T>) -> Fut,
) -> Result<T, String>
where
    Fut: Future<Output = Result<String, String>>,
{
    use crate::cli_ui as ui;
    let mut task = ui::task(label);
    let mut work = std::pin::pin!(work);
    let mut noticed = false;
    let result = loop {
        tokio::select! {
            result = &mut work => break result,
            _ = tokio::time::sleep(Duration::from_millis(50)), if !noticed => {
                if cancelled.load(Ordering::Relaxed) {
                    noticed = true;
                    task.set(cleanup.waiting);
                    ui::info(cleanup.notice);
                }
            }
        }
    };
    if !cancelled.load(Ordering::Relaxed) {
        task.clear();
        return result;
    }
    // The work has finished either way; `undo` removes what it made.
    task.set(cleanup.removing);
    match undo(result.ok()).await {
        Ok(said) => task.done(&said),
        Err(said) => task.fail(&said),
    }
    Err(crate::wire::cancelled(""))
}

/// 24 hours, 7 days and 1 hour, in the order the expiry question lists them.
pub(crate) const EXPIRY_SECONDS: [u64; 3] = [86400, 604800, 3600];

/// The expiry question's choices, in [`EXPIRY_SECONDS`] order.
pub(crate) fn expiry_choices() -> [crate::cli_ui::Choice; 3] {
    use crate::cli_ui::Choice;
    [
        Choice::new("24 hours", "one day"),
        Choice::new("7 days", "one week"),
        Choice::new("1 hour", "short session"),
    ]
}

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
    let grants = listing["grants"]
        .as_array()
        .ok_or("Sharing returned no recipient list")?;
    let active = grants
        .iter()
        .filter(|grant| matches!(grant["status"].as_str(), Some("online" | "offline")))
        .count();
    // A failed attempt takes back only the access it made, never anything that was here before.
    let existing: HashSet<String> = grants.iter().filter_map(share_id).map(str::to_owned).collect();
    let available = 128usize.saturating_sub(active);
    if available == 0 {
        return Err("The maximum of 128 recipients has been reached. Revoke unused recipients with yougori remote revoke ID --yes.".into());
    }
    // The draft survives going back, so earlier answers are offered again.
    let mut count = 1;
    let mut names: Vec<String> = vec![];
    let mut secrets: Vec<Zeroizing<String>> = vec![];
    let mut expiry = 0;
    // "Not now" at the confirmation goes on to the tool without adding anyone.
    let mut not_now = false;
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
                    ui::select("Access ends after", &[], &expiry_choices(), expiry)
                })
                .await?;
                Ok(true)
            }
            .await,
            Question::Confirm => async {
                let who = if count == 1 { "1 teammate".to_owned() } else { format!("{count} teammates") };
                let notes = vec![
                    format!("{who} · control of this sandbox, its files, tool sign-in and connected access · access ends after {}", expiry_choices()[expiry].label),
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
                            Choice::new("Not now", "continue without adding teammates"),
                        ],
                        0,
                    )
                })
                .await?;
                not_now = confirm != 0;
                Ok(true)
            }
            .await,
            Question::Done => break,
        };
        steps.next(asked)?;
    }
    drop(steps);
    if not_now {
        return Ok(true);
    }
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
        create_recipients(id, &recipients, &Access::CONTROL, expires, &existing, |method, params| {
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
    const SHARE_A: &str = "share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHARE_B: &str = "share-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    fn grant(id: &str, target: &str, name: &str, status: &str) -> Value {
        json!({"id":id,"targetId":target,"username":name,"status":status})
    }
    #[tokio::test]
    async fn multiple_teammates_have_individual_grants_and_one_gateway() {
        let people = [
            recipient("alice", "first password"),
            recipient("bob", "second password"),
        ];
        let mut calls = vec![];
        let links = create_recipients("env-codex", &people, &Access::CONTROL, 2000000000, &HashSet::new(), |method, params| {
            calls.push((method, params));
            let value = match calls.len() {
                1 => json!({"id":SHARE_A}),
                2 => json!({"id":SHARE_B}),
                _ => json!({"url":"https://example.com"}),
            };
            std::future::ready(Ok(value))
        })
        .await
        .unwrap();
        assert_eq!(links[0], LINK);
        assert!(links[1].ends_with(SHARE_B));
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
            assert_eq!(request["folder"], Value::Null);
            assert_eq!(request["acknowledgeExistingAccess"], true);
            assert_eq!(request["expiresAt"], 2000000000u64);
        }
    }
    #[tokio::test]
    async fn folder_access_names_its_folder_and_acknowledges_nothing_else() {
        let mut requests = vec![];
        create_recipients(
            "env-site",
            &[recipient("alice", "first password")],
            &Access { permission: "view", folder: Some("/workspace") },
            2000000000,
            &HashSet::new(),
            |method, params| {
                requests.push(params);
                std::future::ready(Ok(if method == "create_remote_share" { json!({"id":SHARE_A}) } else { json!({"url":"https://example.com"}) }))
            },
        )
        .await
        .unwrap();
        let request = &requests[0]["request"];
        assert_eq!((request["permission"].as_str(), request["folder"].as_str()), (Some("view"), Some("/workspace")));
        assert_eq!(request["acknowledgeExistingAccess"], false);
    }
    #[tokio::test]
    async fn a_failure_part_way_takes_back_every_new_access_including_one_a_failed_call_made() {
        let people = [
            recipient("alice", "first password"),
            recipient("bob", "second password"),
        ];
        // Before this attempt: carol, and an older access of alice's that must stay.
        let existing: HashSet<String> = ["share-cccccccccccccccccccccccccccccccc", "share-dddddddddddddddddddddddddddddddd"].map(str::to_owned).into();
        let mut calls: Vec<(&str, Value)> = vec![];
        let error = create_recipients("env-codex", &people, &Access::CONTROL, 2000000000, &existing, |method, params| {
            calls.push((method, params));
            std::future::ready(match (method, calls.len()) {
                ("create_remote_share", 1) => Ok(json!({"id":SHARE_A})),
                // The call failed here, but the engine still made bob's access.
                ("create_remote_share", _) => Err("request timed out".into()),
                ("list_remote_shares", _) => Ok(json!({"grants":[
                    grant(SHARE_A, "env-codex", "alice", "offline"),
                    grant(SHARE_B, "env-codex", "bob", "offline"),
                    grant("share-cccccccccccccccccccccccccccccccc", "env-codex", "carol", "online"),
                    grant("share-dddddddddddddddddddddddddddddddd", "env-codex", "alice", "online"),
                    grant("share-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "env-other", "bob", "online"),
                ]})),
                _ => Ok(Value::Null),
            })
        })
        .await
        .unwrap_err();
        assert_eq!(
            calls.iter().map(|c| c.0).collect::<Vec<_>>(),
            ["create_remote_share", "create_remote_share", "list_remote_shares", "remove_remote_share", "remove_remote_share"],
            "no retry, no gateway, and only this attempt's access is removed"
        );
        assert_eq!(calls[3].1["shareId"], SHARE_A);
        assert_eq!(calls[4].1["shareId"], SHARE_B);
        assert_eq!(error, "Adding bob did not finish (request timed out). The access just created for alice and bob was taken back, so nothing is shared.");
        assert!(!error.contains("share-") && !error.contains("password"));
        let error = create_recipients(
            "env-codex",
            &[
                recipient("alice", "first password"),
                recipient("Alice", "second password"),
            ],
            &Access::CONTROL,
            2000000000,
            &HashSet::new(),
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
    async fn a_gateway_that_cannot_start_leaves_no_new_access_and_never_recreates_it() {
        let mut methods = vec![];
        let error = create_recipients(
            "env-codex",
            &[recipient("alice", "first password")],
            &Access::CONTROL,
            2000000000,
            &HashSet::new(),
            |method, _| {
                methods.push(method);
                std::future::ready(match method {
                    "create_remote_share" => Ok(json!({"id":SHARE_A})),
                    "start_remote_tunnel" => Err("tunnel unavailable".into()),
                    "list_remote_shares" => Ok(json!({"grants":[grant(SHARE_A, "env-codex", "alice", "offline")]})),
                    _ => Ok(Value::Null),
                })
            },
        )
        .await
        .unwrap_err();
        assert_eq!(methods, ["create_remote_share", "start_remote_tunnel", "list_remote_shares", "remove_remote_share"]);
        assert_eq!(error, "The sharing gateway could not start (tunnel unavailable). The access just created for alice was taken back, so nothing is shared.");
    }
    #[tokio::test]
    async fn access_that_cannot_be_taken_back_is_named_with_the_command_that_removes_it() {
        for (revoke_works, expected) in [
            (true, "The sharing gateway could not start (offline). The access just created for alice was taken back, so nothing is shared."),
            (false, "The sharing gateway could not start (offline). alice still has access; take it away with yougori remote revoke share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --yes."),
        ] {
            let mut methods = vec![];
            let error = create_recipients("env-codex", &[recipient("alice", "first password")], &Access::CONTROL, 2000000000, &HashSet::new(), |method, _| {
                methods.push(method);
                std::future::ready(match method {
                    "create_remote_share" => Ok(json!({"id":SHARE_A})),
                    "update_remote_share" if revoke_works => Ok(Value::Null),
                    _ => Err("offline".into()),
                })
            })
            .await
            .unwrap_err();
            assert_eq!(methods, ["create_remote_share", "start_remote_tunnel", "list_remote_shares", "remove_remote_share", "update_remote_share"]);
            assert_eq!(error, expected);
        }
    }
    #[test]
    fn people_are_named_in_plain_sentences() {
        assert_eq!(names([]), "nobody");
        assert_eq!(names(["alice"]), "alice");
        assert_eq!(names(["alice", "bob"]), "alice and bob");
        assert_eq!(names(["alice", "bob", "carol"]), "alice, bob and carol");
        let nothing_made = TakenBack { made: vec![], left: vec![] };
        assert_eq!(nothing_made.sentence("Adding alice did not finish (busy)"), "Adding alice did not finish (busy). Nothing was shared.");
        let two_left = TakenBack { made: vec![], left: vec![("alice".into(), SHARE_A.into()), ("bob".into(), SHARE_B.into())] };
        assert!(two_left.sentence("Failed").starts_with("Failed. alice and bob still have access; take it away with yougori remote revoke share-a"));
    }
    #[tokio::test]
    async fn a_cancelled_creation_finishes_then_removes_what_it_made() {
        use std::sync::{atomic::AtomicUsize, Mutex};
        let cleanup = Cleanup { waiting: "waiting", notice: "notice", removing: "removing" };
        let counter = AtomicUsize::new(0);
        let given = Mutex::new(Vec::new());
        let (undone, seen) = (&counter, &given);
        let undo = move |made: Option<i32>| async move {
            undone.fetch_add(1, Ordering::SeqCst);
            seen.lock().unwrap().push(made);
            Ok::<_, String>("Cancelled. codex was removed again".to_owned())
        };
        // Not cancelled: the work's own answer, and nothing is undone.
        let calm = AtomicBool::new(false);
        assert_eq!(finish_or_undo(&calm, "Creating codex", &cleanup, async { Ok::<_, String>(7) }, undo).await, Ok(7));
        assert_eq!(undone.load(Ordering::SeqCst), 0);
        // Cancelled while the engine works: the work still finishes, then its answer is undone.
        let finished = AtomicBool::new(false);
        let cancelled = AtomicBool::new(true);
        let work = async {
            tokio::time::sleep(Duration::from_millis(80)).await;
            finished.store(true, Ordering::SeqCst);
            Ok::<_, String>(7)
        };
        assert_eq!(finish_or_undo(&cancelled, "Creating codex", &cleanup, work, undo).await, Err(crate::wire::cancelled("")));
        assert!(finished.load(Ordering::SeqCst), "the request the engine had was not abandoned");
        assert_eq!(undone.load(Ordering::SeqCst), 1);
        // A creation that failed after a cancel still looks for what it made, with no answer to go by.
        let failed = async { Err::<i32, String>("no room".into()) };
        assert_eq!(finish_or_undo(&cancelled, "Creating codex", &cleanup, failed, undo).await, Err(crate::wire::cancelled("")));
        assert_eq!(*given.lock().unwrap(), [Some(7), None]);
    }
    #[test]
    fn only_an_environment_the_request_made_is_ever_chosen() {
        let env = |id: &str, name: &str| json!({"id":id,"name":name,"description":"Yougori tool · codex"});
        let named = |env: &Value| env["name"] == "codex";
        let before: HashSet<String> = ["env-old".to_owned()].into();
        // A same-named environment already existed and nothing new appeared: nothing is chosen.
        let after = [env("env-old", "codex")];
        assert_eq!(made_by_request(&after, &before, None, named), Made::Nothing);
        // The engine's own answer names an environment that existed before: still never chosen.
        assert_eq!(made_by_request(&after, &before, Some("env-old"), named), Made::Before);
        // One new environment beside the old one: that one, by its returned ID or by its name.
        let after = [env("env-old", "codex"), env("env-new", "codex")];
        assert_eq!(made_by_request(&after, &before, Some("env-new"), named), Made::One("env-new"));
        assert_eq!(made_by_request(&after, &before, None, named), Made::One("env-new"));
        // Two new environments match: neither can be told to be this request's.
        let after = [env("env-old", "codex"), env("env-a", "codex"), env("env-b", "codex")];
        assert_eq!(made_by_request(&after, &before, None, named), Made::Unclear);
        // The returned ID settles it, and counts for nothing once that environment is gone.
        assert_eq!(made_by_request(&after, &before, Some("env-b"), named), Made::One("env-b"));
        assert_eq!(made_by_request(&after, &before, Some("env-gone"), named), Made::Nothing);
    }
    #[tokio::test]
    async fn a_cancelled_connection_removes_only_the_node_it_added() {
        let runtime = shared_runtime(LINK).unwrap();
        let node = |id: &str| json!({"id":id,"name":"codex","runtime":runtime});
        let listed: HashSet<String> = ["env-listed".to_owned()].into();
        let state = |nodes: Vec<Value>| json!({"environments":nodes});
        for (made, after, deleted, said) in [
            // Already in the list before: it stays.
            (Some(state(vec![node("env-listed")])), vec![node("env-listed")], None, "Cancelled. The shared sandbox stays in your list, as before."),
            // Added by this connection: closed again.
            (Some(state(vec![node("env-new")])), vec![node("env-new")], Some("env-new"), "Cancelled. The connection was closed again."),
            // The connection failed and only the old node is there: nothing is removed.
            (None, vec![node("env-listed")], None, "Cancelled. Nothing was connected."),
        ] {
            let mut removed = vec![];
            let result = disconnect_cancelled(LINK, Some(&listed), made, |method, params| {
                if method == "delete_environment" {
                    removed.push(params["environmentId"].as_str().unwrap_or("").to_owned());
                }
                std::future::ready(Ok(state(after.clone())))
            })
            .await;
            assert_eq!(result.unwrap(), said);
            assert_eq!(removed, deleted.map(str::to_owned).into_iter().collect::<Vec<_>>());
        }
        // Two new nodes for one link and no answer: none is removed, and the person is told how.
        let mut methods = vec![];
        let error = disconnect_cancelled(LINK, Some(&listed), None, |method, _| {
            methods.push(method);
            std::future::ready(Ok(state(vec![node("env-a"), node("env-b")])))
        })
        .await
        .unwrap_err();
        assert_eq!(methods, ["get_platform_state"]);
        assert!(error.contains("Nothing was removed") && error.contains("yougori rm NAME --yes"), "{error}");
        // A list from before that never came is not an empty one: the node that was there before
        // the request, answered back by the engine, is not removed.
        assert_eq!(environment_ids(&json!({"error": "malformed"})), None);
        assert_eq!(environment_ids(&json!({"environments": []})), Some(HashSet::new()));
        let mut methods = vec![];
        let error = disconnect_cancelled(LINK, None, Some(state(vec![node("env-listed")])), |method, _| {
            methods.push(method);
            std::future::ready(Ok(state(vec![node("env-listed")])))
        })
        .await
        .unwrap_err();
        assert!(methods.is_empty(), "nothing was looked up, let alone removed");
        assert!(error.contains("Nothing was removed") && error.contains("could not tell"), "{error}");
        // An answer afterwards that does not list them never reads as "nothing was connected".
        let mut methods = vec![];
        let error = disconnect_cancelled(LINK, Some(&listed), None, |method, _| {
            methods.push(method);
            std::future::ready(Ok(json!({"error": "malformed"})))
        })
        .await
        .unwrap_err();
        assert_eq!(methods, ["get_platform_state"]);
        assert!(error.contains("could not be checked") && !error.contains("Nothing was connected"), "{error}");
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
