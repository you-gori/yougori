//! Host-owned controls for a guest shell. Only keyboard input opens this menu;
//! guest escape sequences never grant access to host actions.
use super::{call, SessionExit};
use crate::cli_ui::{self as kit, Choice};
use crate::tool_sharing::{uninterrupted, Access, Recipient, EXPIRY_SECONDS};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    io::{self, Write},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub(super) fn clean(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

fn paint(text: &str, code: &str) -> String {
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
        || std::env::var("TERM").is_ok_and(|v| v == "dumb")
    {
        text.into()
    } else {
        format!("\x1b[{code}m{text}\x1b[0m")
    }
}

pub(super) fn line(text: &str) -> Result<(), String> {
    let mut out = io::stdout().lock();
    write!(out, "{}\r\n", crate::presentation::text(text)).map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

pub(super) struct Context {
    id: String,
    pub name: String,
    /// How a command names this environment: its name where that is unambiguous, else its ID.
    pub handle: String,
    pub local_shell: bool,
    details: String,
    installable: bool,
    sandbox_controls: bool,
    /// Whether this environment can be shared from here. One shared with you cannot: only its
    /// owner can share it, and the engine refuses.
    shareable: bool,
}

/// Leaves the menu for the shell, as "Back to the shell" does.
const LEAVE: &str = "\u{1}yougori leave the menu";

/// Why an environment shared with you offers no sharing of its own.
const NOT_OWNER: &str = "This environment was shared with you, so only its owner can share it or change who has access.";

/// What a person may do with an environment shared with them: the request's word, the choice
/// and what it means.
const ACCESS: [(&str, &str, &str); 3] = [
    ("view", "View one folder", "they can read the files in one folder"),
    ("edit", "Edit one folder", "they can read and change the files in one folder"),
    ("control", "Control this environment", "they can run commands, change any file, and start or stop it"),
];

/// What the share questions have collected so far. Going back keeps every answer.
#[derive(Default)]
struct ShareAnswers {
    /// An index into [`ACCESS`].
    access: usize,
    folder: String,
    username: String,
    password: Zeroizing<String>,
    /// An index into [`EXPIRY_SECONDS`].
    expiry: usize,
}

#[derive(Debug, PartialEq)]
enum ShareQuestion {
    Access,
    Folder,
    Username,
    Password,
    Expiry,
    Confirm,
    /// Control of the whole environment has no folder to ask about.
    Skipped,
    Done,
}

/// The question a share step asks: what they may do, the folder unless they control the whole
/// environment, their username and password, when access ends, then the confirmation.
fn share_question(step: usize, access: usize) -> ShareQuestion {
    match step {
        0 => ShareQuestion::Access,
        1 if ACCESS[access].0 == "control" => ShareQuestion::Skipped,
        1 => ShareQuestion::Folder,
        2 => ShareQuestion::Username,
        3 => ShareQuestion::Password,
        4 => ShareQuestion::Expiry,
        5 => ShareQuestion::Confirm,
        _ => ShareQuestion::Done,
    }
}

fn folder(entry: &str) -> Result<String, String> {
    let folder = entry.trim();
    if !folder.starts_with('/') || folder == "/" {
        return Err("Choose one folder inside the environment, as an absolute path such as /workspace.".into());
    }
    Ok(folder.to_owned())
}

/// What a recipient may do, and whether they can connect now, in words.
fn access_words(grant: &Value) -> String {
    let folder = || clean(grant["folder"].as_str().unwrap_or("one folder"));
    let what = match grant["permission"].as_str() {
        Some("view") => format!("can view {}", folder()),
        Some("edit") => format!("can edit {}", folder()),
        Some("control") => "controls this environment".to_owned(),
        _ => "has access".to_owned(),
    };
    let state = match grant["status"].as_str() {
        Some("online") => "can connect now",
        Some("offline") => "sharing is off",
        Some("revoked") => "access taken away",
        Some("expired") => "access ended",
        _ => "state unknown",
    };
    format!("{what} · {state}")
}

fn active(grant: &Value) -> bool {
    matches!(grant["status"].as_str(), Some("online" | "offline"))
}

/// What kind of environment this is, in words: never an image digest or a sharing address.
fn kind_words(env: &Value) -> String {
    let runtime = env["runtime"].as_str().unwrap_or("");
    if runtime.starts_with("shared://") {
        return "shared with you".into();
    }
    match env["kind"].as_str() {
        Some("microVm") => "microVM".into(),
        Some("cloud") => "cloud server".into(),
        Some("container") if runtime == crate::container_tools::DEFAULT_IMAGE => "container · Ubuntu 24.04".into(),
        Some("container") => match runtime.split('@').next().map(clean).filter(|image| !image.is_empty()) {
            Some(image) => format!("container · {image}"),
            None => "container".into(),
        },
        _ => clean(if runtime.is_empty() { "Guest shell" } else { runtime }),
    }
}

impl Context {
    pub fn new(env: &Value, environments: &[Value]) -> Self {
        // Local containers and microVMs; installers support only Yougori's built-in microVM guest.
        let local = crate::sandbox_stop::is_local_sandbox(env);
        let microvm = env["kind"] == "microVm";
        let cpu = env["resourcePolicy"]["cpu"]["preferred"].as_f64();
        let memory = env["resourcePolicy"]["memoryGb"]["preferred"].as_f64();
        let mut details = vec![kind_words(env)];
        if let Some(cpu) = cpu {
            details.push(format!("{cpu} CPU"));
        }
        if let Some(memory) = memory {
            details.push(format!("{memory} GB memory"));
        }
        let id = env["id"].as_str().unwrap_or("");
        Self {
            id: id.into(),
            name: clean(env["name"].as_str().unwrap_or("Environment")),
            handle: crate::container_tools::handle(environments, id),
            local_shell: local,
            installable: local && env["networkAccess"] != false && (!microvm || env["runtime"] == "builtin:alpine"),
            sandbox_controls: local,
            details: details.join(" · "),
            shareable: !env["runtime"].as_str().is_some_and(|runtime| runtime.starts_with("shared://")) && env["kind"] != "computerBranch",
        }
    }

    pub fn welcome(&self) -> Result<(), String> {
        // Clear the viewport, preserving the invoking terminal's scrollback.
        print!("\x1b[2J\x1b[H");
        line("")?;
        line(&format!(
            "  {}  {}",
            paint("Yougori", "1;36"),
            paint(&self.name, "1")
        ))?;
        line(&format!("  {}", paint(&self.details, "90")))?;
        line("")?;
        line(&format!("  {}  Tools & sharing\r\n  {}  Return to your PC terminal\r\n  {}  {}",
            paint("Ctrl+G", "36"), paint("Ctrl+D / exit / Ctrl+]", "36"), paint("Ctrl+C", "36"),
            if self.sandbox_controls {"Cancel / Stop sandbox / Stop and delete"} else {"Interrupt the guest command"}))?;
        line("")?;
        line(&format!(
            "  {}",
            paint(
                "Your environment and files stay available when you leave.",
                "90"
            )
        ))?;
        line("")
    }

    /// The Ctrl+G menu. Its questions work like every other question in the CLI: each one after
    /// the first offers Back (Esc or the Back row), the first one's Back returns to this menu, and
    /// Ctrl+C returns to the shell from anywhere.
    pub async fn menu(&self) -> Result<(), String> {
        let _screen = MenuScreen::enter()?;
        let mut action = 0;
        loop {
            let mut steps = kit::Wizard::new();
            let outcome = loop {
                let asked = match steps.step() {
                    0 => self.choose(&mut action),
                    1 => match action {
                        0 => self.install().await,
                        1 => self.share().await,
                        2 => self.shares().await,
                        _ => self.help(),
                    },
                    _ => break Ok(()),
                };
                if let Err(error) = steps.next(asked) {
                    break Err(error);
                }
            };
            drop(steps);
            match outcome {
                Ok(()) => {}
                Err(error) if error == LEAVE || error == kit::CANCELLED || error == kit::BACK => return Ok(()),
                Err(error) => kit::warn(&clean(&error)),
            }
            // What an action showed stays on screen until the person moves on.
            let next = kit::without_back(|| {
                kit::select(
                    "What next?",
                    &[],
                    &[
                        Choice::new("Back to the shell", "close this menu"),
                        Choice::new("Back to the menu", "choose another action"),
                    ],
                    0,
                )
            });
            if next != Ok(1) {
                return Ok(());
            }
        }
    }

    /// The menu itself, its first question: Esc and Ctrl+C both return to the shell.
    fn choose(&self, action: &mut usize) -> Result<bool, String> {
        let install = if self.installable {
            Choice::new("Install a tool", "add a coding tool to this environment")
        } else {
            Choice::new("Install a tool", "needs a local container or microVM with Internet access").disabled()
        };
        let (share, manage) = if self.shareable {
            (
                Choice::new("Share this environment", "give one person access with a password"),
                Choice::new("Manage sharing", "see who has access, or take it away"),
            )
        } else {
            (
                Choice::new("Share this environment", "shared with you; only its owner can share it").disabled(),
                Choice::new("Manage sharing", "shared with you; only its owner manages its sharing").disabled(),
            )
        };
        let choices = [
            install,
            share,
            manage,
            Choice::new("Terminal help", "keys, and how to come back here"),
            Choice::new("Back to the shell", "close this menu"),
        ];
        let index = kit::select(&format!("Yougori · {}", self.name), &[], &choices, *action)?;
        if index == choices.len() - 1 {
            return Err(LEAVE.into());
        }
        *action = index;
        Ok(true)
    }

    fn help(&self) -> Result<bool, String> {
        kit::step("Terminal keys");
        kit::info(if self.sandbox_controls {"Ctrl+C opens Cancel / Stop sandbox / Stop and delete. Cancel returns without interrupting the guest."}
            else {"Ctrl+C interrupts a command inside this environment."});
        kit::info("Ctrl+D at an empty shell prompt, exit, or Ctrl+] returns to your PC terminal.");
        kit::info("Ctrl+G opens tools and sharing at the shell. Full-screen apps keep their own Ctrl+G shortcut.");
        kit::info("Installers run in their own shell inside this environment. Its current shell stays open.");
        kit::info(&format!("Reconnect: {}", shell_words::join(["yougori", "terminal", &self.handle])));
        Ok(false)
    }

    async fn install(&self) -> Result<bool, String> {
        if !self.installable {
            return Err(
                "Tool installers need a local container or built-in microVM with Internet access enabled.".into(),
            );
        }
        let tools = crate::container_tools::TOOLS;
        let choices: Vec<Choice> = tools.iter().map(|tool| Choice::new(*tool, "")).collect();
        let tool = tools[kit::select("Which tool should be installed?", &[], &choices, 0)?];
        kit::info(&format!(
            "Installing {tool} in {}. Sign in inside the sandbox when you open it.",
            self.name
        ));
        // A separate owned PTY cannot inject an installer into a busy shell.
        // The tool launcher checks/installs the binary and verifies --version.
        match Box::pin(super::attach_tool_session(&self.id, tool, &["--version".into()])).await? {
            SessionExit::Completed => {}
            SessionExit::Detached => {
                kit::info(&format!("{tool} was not installed. Choose it again to finish."));
                return Ok(true);
            }
            SessionExit::Stopped => {
                kit::info("The sandbox was stopped, so nothing more was installed.");
                return Ok(true);
            }
        }
        let state = call("get_platform_state", json!({})).await.unwrap_or_default();
        let environments = state["environments"].as_array().map_or(&[][..], Vec::as_slice);
        kit::step(&format!("{tool} is ready. Run {tool} in the shell, or open it from your PC terminal with:"));
        kit::info(&crate::container_tools::reconnect_command(tool, &self.id, environments));
        Ok(true)
    }

    /// Who to share with, what they may do and for how long. Nothing is created before the
    /// last answer.
    async fn share(&self) -> Result<bool, String> {
        if !self.shareable {
            return Err(NOT_OWNER.into());
        }
        let mut answers = ShareAnswers::default();
        let mut steps = kit::Wizard::new();
        loop {
            let asked = match share_question(steps.step(), answers.access) {
                ShareQuestion::Access => {
                    let choices = ACCESS.map(|(_, label, hint)| Choice::new(label, hint));
                    kit::select("What may they do?", &[], &choices, answers.access).map(|index| {
                        answers.access = index;
                        true
                    })
                }
                ShareQuestion::Folder => {
                    let initial = if answers.folder.is_empty() { "/workspace" } else { &answers.folder };
                    let note = ["An absolute path inside the environment. Only this folder is shared.".to_owned()];
                    kit::input_noted("Which folder?", &note, initial, &folder).map(|chosen| {
                        answers.folder = chosen;
                        true
                    })
                }
                ShareQuestion::Username => {
                    let note = ["They type it with the password to connect.".to_owned()];
                    kit::input_noted("Their username", &note, &answers.username, &crate::tool_sharing::username).map(|name| {
                        answers.username = name;
                        true
                    })
                }
                ShareQuestion::Password => {
                    let label = format!("{} · password", answers.username);
                    kit::input(&label, "", true, &|entry| {
                        crate::tool_sharing::password(entry)?;
                        Ok(entry.into())
                    })
                    .map(|secret| {
                        answers.password = Zeroizing::new(secret);
                        true
                    })
                }
                ShareQuestion::Expiry => {
                    kit::select("Access ends after", &[], &crate::tool_sharing::expiry_choices(), answers.expiry).map(|index| {
                        answers.expiry = index;
                        true
                    })
                }
                ShareQuestion::Confirm => match kit::select("Share this environment?", &self.share_notes(&answers), &[
                    Choice::new("Share", "turn on password-protected sharing for them"),
                    Choice::new("Don't share", "return without changing anything"),
                ], 0) {
                    Ok(0) => Ok(true),
                    Ok(_) => return Ok(false),
                    Err(error) => Err(error),
                },
                ShareQuestion::Skipped => Ok(false),
                ShareQuestion::Done => break,
            };
            steps.next(asked)?;
        }
        drop(steps);
        self.create_share(&answers).await
    }

    /// What the confirmation says will happen.
    fn share_notes(&self, answers: &ShareAnswers) -> Vec<String> {
        let (permission, label, _) = ACCESS[answers.access];
        let what = if permission == "control" { "the whole environment".to_owned() } else { answers.folder.clone() };
        let ends = crate::tool_sharing::expiry_choices()[answers.expiry].label.clone();
        let mut notes = vec![format!("{} · {} · {what} · access ends after {ends}", answers.username, label.to_lowercase())];
        if permission == "control" {
            notes.push("Control includes commands, every file, starting and stopping it, and access already connected to this environment.".into());
        }
        notes.push("This turns on a password-protected public link. Everyone whose access is still active can reach it too.".into());
        notes
    }

    /// Creates the access, turns sharing on and shows the link. When anything fails part way,
    /// the access is taken back again and the message says so.
    async fn create_share(&self, answers: &ShareAnswers) -> Result<bool, String> {
        let (permission, _, _) = ACCESS[answers.access];
        let folder = (permission != "control").then_some(answers.folder.as_str());
        let listing = kit::busy("Checking who already has access", call("list_remote_shares", json!({}))).await?;
        let existing: HashSet<String> = listing["grants"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|grant| grant["id"].as_str())
            .map(str::to_owned)
            .collect();
        let recipients = [Recipient { username: answers.username.clone(), password: answers.password.clone() }];
        let expires = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() + EXPIRY_SECONDS[answers.expiry];
        let (links, _) = uninterrupted(
            &format!("Sharing {} with {}", self.name, answers.username),
            ["Sharing is on", "Sharing could not start"],
            "finishing first",
            crate::tool_sharing::create_recipients(&self.id, &recipients, &Access { permission, folder }, expires, &existing, |method, params| {
                call(method, params)
            }),
        )
        .await;
        let link = links?.pop().ok_or("Sharing returned no link")?;
        kit::step(&format!("Share link: {link}"));
        kit::info(&format!("Username: {}", answers.username));
        kit::info(&format!(
            "They connect with: yougori connect {} {}",
            shell_words::quote(&link),
            shell_words::quote(&answers.username)
        ));
        kit::info("Yougori asks them for the password, so send it to them separately. Manage sharing takes this access away again.");
        Ok(true)
    }

    /// Who has access to this environment, and taking it away. Turning sharing on again for
    /// the access that is still active is here too.
    async fn shares(&self) -> Result<bool, String> {
        if !self.shareable {
            return Err(NOT_OWNER.into());
        }
        let listing = kit::busy("Checking who has access", call("list_remote_shares", json!({}))).await?;
        let grants: Vec<Value> = listing["grants"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|grant| grant["targetId"] == self.id.as_str())
            .cloned()
            .collect();
        if !grants.iter().any(active) {
            kit::info(if grants.is_empty() {
                "Nobody has access to this environment yet. Share this environment adds someone."
            } else {
                "Nobody has active access to this environment. Share this environment adds someone."
            });
            return Ok(false);
        }
        let off = grants.iter().any(|grant| grant["status"] == "offline");
        let mut picked = 0;
        let mut steps = kit::Wizard::new();
        loop {
            let asked = match steps.step() {
                0 => {
                    let mut choices: Vec<Choice> = grants
                        .iter()
                        .map(|grant| {
                            let choice = Choice::new(clean(grant["username"].as_str().unwrap_or("someone")), access_words(grant));
                            if active(grant) { choice } else { choice.disabled() }
                        })
                        .collect();
                    if off {
                        choices.push(Choice::new("Turn sharing on again", "everyone with active access can connect again"));
                    }
                    kit::select("Who has access", &[], &choices, picked).map(|index| {
                        picked = index;
                        true
                    })
                }
                1 if picked == grants.len() => self.sharing_on().await,
                1 => self.take_away(&grants[picked]).await,
                _ => break,
            };
            steps.next(asked)?;
        }
        Ok(true)
    }

    async fn take_away(&self, grant: &Value) -> Result<bool, String> {
        let name = clean(grant["username"].as_str().unwrap_or("this person"));
        let mut notes = vec![access_words(grant)];
        if let Some(link) = grant["link"].as_str() {
            notes.push(format!("Share link: {}", clean(link)));
        }
        let choice = kit::select(&format!("Take away {name}'s access?"), &notes, &[
            Choice::new("Keep their access", "change nothing"),
            Choice::new("Take it away", "they are disconnected and cannot connect again"),
        ], 0)?;
        if choice == 1 {
            let (taken, _) = uninterrupted(
                &format!("Taking away {name}'s access"),
                [&format!("{name} no longer has access"), "Their access could not be taken away"],
                "finishing first",
                call("update_remote_share", json!({"shareId":grant["id"],"revoke":true})),
            )
            .await;
            taken?;
        }
        Ok(true)
    }

    async fn sharing_on(&self) -> Result<bool, String> {
        let notes = ["Everyone whose access is still active can connect again, to every environment you share.".to_owned()];
        let choice = kit::select("Turn sharing on again?", &notes, &[
            Choice::new("Turn it on", "start the password-protected link"),
            Choice::new("Leave it off", "change nothing"),
        ], 0)?;
        if choice == 0 {
            let (gateway, _) = uninterrupted("Turning sharing on", ["Sharing is on", "Sharing could not start"], "finishing first", call("start_remote_tunnel", json!({}))).await;
            if let Some(url) = gateway?["url"].as_str() {
                kit::info(&format!("Sharing address: {}", clean(url)));
            }
        }
        Ok(true)
    }
}

/// The menu's own screen, with the CLI's painter showing on it. The guest's screen comes back
/// untouched when it closes.
struct MenuScreen(Option<kit::Visible>);
impl MenuScreen {
    fn enter() -> Result<Self, String> {
        print!("\x1b[?1049h\x1b[2J\x1b[H");
        io::stdout().flush().map_err(|e| e.to_string())?;
        Ok(Self(Some(kit::Visible::new())))
    }
}
impl Drop for MenuScreen {
    fn drop(&mut self) {
        // The painter steps aside first, so none of it is left on the guest's screen.
        drop(self.0.take());
        print!("\x1b[0m\x1b[?25h\x1b[?1049l");
        let _ = io::stdout().flush();
    }
}

pub(super) struct StopOverlay { guest_alternate: bool }
impl StopOverlay {
    pub fn enter(guest_alternate: bool) -> Result<Self, String> {
        // A full-screen guest already owns the alternate buffer. Return to the
        // host screen for controls, then restore/repaint the guest on Cancel.
        print!("{}", if guest_alternate {"\x1b[?1049l"} else {"\x1b[?1049h\x1b[2J\x1b[H"});
        io::stdout().flush().map_err(|e| e.to_string())?;
        crate::cli_ui::pause(false);
        Ok(Self { guest_alternate })
    }
}
impl Drop for StopOverlay {
    fn drop(&mut self) {
        crate::cli_ui::pause(true);
        print!("{}", if self.guest_alternate {"\x1b[?1049h"} else {"\x1b[?1049l"});
        let _ = io::stdout().flush();
    }
}

pub(super) fn shell_setup(name: &str, marker: &str) -> String {
    // Bash expands PS1 again, even if assigned with shell quoting. Names must
    // not carry $, backticks, backslashes or prompt escape sequences into PS1.
    let slug: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || " _-.".contains(*c))
        .take(32)
        .collect();
    let prompt = format!(
        "yougori {}:\\w $ ",
        if slug.is_empty() { "guest" } else { &slug }
    );
    let (head, tail) = marker.split_at(marker.len() / 2);
    format!(
        "export PATH=\"$HOME/.local/share/yougori/bin:$HOME/.local/bin:$PATH\"; {}; export PS1={}; printf '%s%s' {} {}",
        super::TOOL_ENV,
        shell_words::quote(&prompt),
        shell_words::quote(head),
        shell_words::quote(tail)
    )
}

#[derive(Default)]
pub(super) struct Interrupts {
    last: Option<Instant>,
    count: u8,
    escape: Vec<u8>,
    osc: bool,
    pasted: bool,
}
#[derive(Default)]
pub(super) struct Actions {
    pub menu: bool,
    pub exit_hint: bool,
    pub stop: bool,
}

pub(super) fn filter_input(
    bytes: &mut Vec<u8>,
    interrupts: &mut Interrupts,
    menu_enabled: bool,
    sandbox_controls: bool,
) -> Actions {
    let mut action = Actions::default();
    bytes.retain(|byte| {
        // Terminal replies and bracketed paste are data, not host shortcuts.
        // In particular, an OSC reply's BEL must not open the sharing menu.
        if interrupts.osc {
            if *byte == 7 || (*byte == b'\\' && interrupts.escape.last() == Some(&27)) {
                interrupts.osc = false;
                interrupts.escape.clear();
            } else {
                interrupts.escape.clear();
                if *byte == 27 {
                    interrupts.escape.push(*byte);
                }
            }
            return true;
        }
        if *byte == 27 {
            interrupts.escape.clear();
            interrupts.escape.push(*byte);
            return true;
        }
        // A lone Escape followed by a control key is two key presses, not one
        // escape sequence: Ctrl+C after Esc still opens the stop menu.
        if interrupts.escape.len() == 1 && *byte < 0x20 {
            interrupts.escape.clear();
        }
        if !interrupts.escape.is_empty() {
            interrupts.escape.push(*byte);
            if interrupts.escape == b"\x1b]" {
                interrupts.osc = true;
                interrupts.escape.clear();
            } else if (interrupts.escape.len() == 2 && *byte != b'[')
                || (interrupts.escape.len() > 2 && (0x40..=0x7e).contains(byte))
            {
                if interrupts.escape == b"\x1b[200~" {
                    interrupts.pasted = true;
                }
                if interrupts.escape == b"\x1b[201~" {
                    interrupts.pasted = false;
                }
                interrupts.escape.clear();
            } else if interrupts.escape.len() > 64 {
                interrupts.escape.clear();
            }
            return true;
        }
        if interrupts.pasted {
            return true;
        }
        if *byte == 7 && menu_enabled {
            action.menu = true;
            return false;
        }
        if *byte == 3 {
            if sandbox_controls {
                action.stop = true;
                return false;
            }
            let now = Instant::now();
            if interrupts
                .last
                .is_none_or(|last| now.duration_since(last) > Duration::from_secs(2))
            {
                interrupts.count = 0;
            }
            interrupts.last = Some(now);
            interrupts.count = interrupts.count.saturating_add(1);
            if interrupts.count >= 3 {
                action.exit_hint = true;
                interrupts.count = 0;
            }
        } else {
            interrupts.count = 0;
        }
        true
    });
    action
}

// Track only the guest's alternate-screen modes. A split escape sequence is
// retained, but arbitrary guest output cannot open the host controls.
#[derive(Default)]
pub(super) struct GuestScreen {
    pub alternate: bool,
    pending: Vec<u8>,
}
impl GuestScreen {
    pub fn feed(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if *byte == 27 {
                self.pending.clear();
                self.pending.push(*byte);
            } else if !self.pending.is_empty() {
                self.pending.push(*byte);
                if self.pending.len() > 2 && (0x40..=0x7e).contains(byte) {
                    if self.pending.starts_with(b"\x1b[?") && matches!(*byte, b'h' | b'l') {
                        let modes = &self.pending[3..self.pending.len() - 1];
                        if modes
                            .split(|b| *b == b';')
                            .any(|m| matches!(m, b"47" | b"1047" | b"1049"))
                        {
                            self.alternate = *byte == b'h';
                        }
                    }
                    self.pending.clear();
                } else if self.pending.len() > 64 {
                    self.pending.clear();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupts_reach_the_guest_and_only_a_burst_shows_exit_guidance() {
        let mut interrupts = Interrupts::default();
        for i in 0..3 {
            let mut bytes = vec![3];
            assert_eq!(
                filter_input(&mut bytes, &mut interrupts, true, false).exit_hint,
                i == 2
            );
            assert_eq!(bytes, [3]);
        }
        let mut bytes = b"a\x03\x03".to_vec();
        assert!(!filter_input(&mut bytes, &mut interrupts, true, false).exit_hint);
        interrupts.last = Some(Instant::now() - Duration::from_secs(3));
        assert!(!filter_input(&mut vec![3], &mut interrupts, true, false).exit_hint);
        let mut bytes = vec![7];
        assert!(filter_input(&mut bytes, &mut interrupts, true, false).menu);
        assert!(bytes.is_empty());
        let mut bytes = vec![7, 4];
        assert!(!filter_input(&mut bytes, &mut interrupts, false, false).menu);
        assert_eq!(bytes, [7, 4]);
    }
    #[test]
    fn guest_fullscreen_modes_work_across_read_boundaries() {
        let mut screen = GuestScreen::default();
        screen.feed(b"hello\x1b[?10");
        screen.feed(b"49h");
        assert!(screen.alternate);
        screen.feed(b"\x1b[?1;1049l");
        assert!(!screen.alternate);
        screen.feed(b"\x1b[?47h");
        assert!(screen.alternate);
        screen.feed(b"\x1b[?47l");
        assert!(!screen.alternate);
        screen.feed(b"text\x07\x1b[31m");
        assert!(!screen.alternate);
    }
    #[test]
    fn prompt_names_cannot_execute_commands_and_marker_is_not_in_echo() {
        let marker = "yougori-ready-123456";
        let command = shell_setup("evil$(touch /tmp/no)`id`\\[\x1b", marker);
        assert!(!command.contains("$("));
        assert!(!command.contains('`'));
        assert!(!command.contains(marker));
        let parts = shell_words::split(command.split("export PS1=").nth(1).unwrap()).unwrap();
        assert!(parts[0].starts_with("yougori "));
        assert_eq!(format!("{}{}", parts[3], parts[4]), marker);
        assert!(command.contains("$HOME/.local/share/yougori/bin:$HOME/.local/bin:$PATH"));
    }
    #[test]
    fn terminal_replies_and_bracketed_paste_cannot_open_host_controls() {
        let mut interrupts = Interrupts::default();
        for data in [
            b"\x1b]0;title".as_slice(),
            b"\x07",
            b"\x1b[200~\x07\x03",
            b"\x03\x03\x1b[201~",
        ] {
            let mut bytes = data.to_vec();
            let actions = filter_input(&mut bytes, &mut interrupts, true, true);
            assert!(!actions.menu && !actions.exit_hint && !actions.stop);
            assert_eq!(bytes, data);
        }
        assert!(filter_input(&mut vec![7], &mut interrupts, true, true).menu);
    }
    #[test]
    fn ctrl_c_is_owned_by_the_stop_menu_before_it_can_interrupt_a_local_tool() {
        for menu_enabled in [true, false] {
            let mut interrupts = Interrupts::default();
            let mut bytes = vec![3, 3, 3];
            let actions = filter_input(&mut bytes, &mut interrupts, menu_enabled, true);
            assert!(actions.stop);
            assert!(bytes.is_empty());
            assert!(!actions.exit_hint);
            let mut bytes = b"hello".to_vec();
            assert!(!filter_input(&mut bytes, &mut interrupts, menu_enabled, true).stop);
            assert_eq!(bytes, b"hello");
        }
        let mut bytes = vec![3];
        assert!(!filter_input(&mut bytes, &mut Interrupts::default(), false, false).stop);
        assert_eq!(bytes, [3]);
    }
    #[test]
    fn ctrl_c_after_a_lone_escape_still_opens_the_stop_menu() {
        let mut interrupts = Interrupts::default();
        let mut escape = vec![27];
        assert!(!filter_input(&mut escape, &mut interrupts, true, true).stop);
        assert_eq!(escape, [27]);
        let mut bytes = vec![3];
        assert!(filter_input(&mut bytes, &mut interrupts, true, true).stop);
        assert!(bytes.is_empty());
        // Escape sequences such as arrow keys are unaffected.
        let mut arrow = b"\x1b[A".to_vec();
        assert!(!filter_input(&mut arrow, &mut interrupts, true, true).stop);
        assert_eq!(arrow, b"\x1b[A");
    }
    #[test]
    fn sharing_asks_every_question_in_order_and_control_has_no_folder() {
        let order = |access: usize| (0..7).map(|step| share_question(step, access)).collect::<Vec<_>>();
        use ShareQuestion::*;
        assert_eq!(order(0), [Access, Folder, Username, Password, Expiry, Confirm, Done]);
        assert_eq!(order(1), [Access, Folder, Username, Password, Expiry, Confirm, Done]);
        // Skipped steps ask nothing, so Back from the username goes straight to the access question.
        assert_eq!(order(2), [Access, Skipped, Username, Password, Expiry, Confirm, Done]);
        assert_eq!(ACCESS.map(|(permission, _, _)| permission), ["view", "edit", "control"]);
        assert_eq!(folder(" /workspace/site ").unwrap(), "/workspace/site");
        for entry in ["", "/", "workspace", "~/site"] {
            assert!(folder(entry).is_err(), "{entry}");
        }
    }
    #[test]
    fn recipients_are_described_in_words_without_ids() {
        let grant = |permission: &str, status: &str| json!({"id":"share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","username":"alice","permission":permission,"folder":"/workspace","status":status});
        assert_eq!(access_words(&grant("view", "online")), "can view /workspace · can connect now");
        assert_eq!(access_words(&grant("edit", "offline")), "can edit /workspace · sharing is off");
        assert_eq!(access_words(&grant("control", "revoked")), "controls this environment · access taken away");
        assert!(!access_words(&grant("control", "expired")).contains("share-"));
        assert!(active(&grant("view", "offline")) && !active(&grant("view", "expired")));
    }
    #[test]
    fn an_environment_shared_with_you_offers_no_sharing_and_names_its_kind_in_words() {
        let shared = json!({"id":"env-r","name":"notes (remote)","kind":"cloud","runtime":"shared://tunnel/0a1b/share-0123456789abcdef0123456789abcdef"});
        let context = Context::new(&shared, std::slice::from_ref(&shared));
        assert!(!context.shareable);
        assert_eq!(context.details, "shared with you");
        let container = json!({"id":"env-c","name":"site","kind":"container","provider":"yougoriOci","runtime":crate::container_tools::DEFAULT_IMAGE});
        let context = Context::new(&container, std::slice::from_ref(&container));
        assert!(context.shareable);
        assert_eq!(context.details, "container · Ubuntu 24.04");
        assert_eq!(kind_words(&json!({"kind":"container","runtime":"node:22@sha256:abc"})), "container · node:22");
        assert_eq!(kind_words(&json!({"kind":"microVm","runtime":"builtin:alpine"})), "microVM");
        assert_eq!(kind_words(&json!({"kind":"cloud","runtime":"cloud://server"})), "cloud server");
    }
    #[test]
    fn reconnect_hints_name_the_environment_unless_the_name_is_ambiguous() {
        let environments = [
            json!({"id":"env-1","name":"site","kind":"container","provider":"yougoriOci","runtime":"ubuntu"}),
            json!({"id":"env-2","name":"notes app","kind":"container"}),
            json!({"id":"env-3","name":"SITE2","kind":"container"}),
            json!({"id":"env-4","name":"site2","kind":"container"}),
        ];
        assert_eq!(Context::new(&environments[0], &environments).handle, "site");
        let spaced = Context::new(&environments[1], &environments);
        assert_eq!(spaced.handle, "notes app", "a name a shell would split is kept and quoted where it is used");
        assert_eq!(shell_words::join(["yougori", "terminal", &spaced.handle]), "yougori terminal 'notes app'");
        assert_eq!(Context::new(&environments[2], &environments).handle, "env-3", "two sandboxes answer to it");
    }
}
