//! Host-owned controls for a guest shell. Only keyboard input opens this menu;
//! guest escape sequences never grant access to host actions.
use super::{call, InputReader};
use serde_json::{json, Value};
use std::{
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
    pub local_shell: bool,
    details: String,
    installable: bool,
    sandbox_controls: bool,
}

impl Context {
    pub fn new(env: &Value) -> Self {
        let provider = env["provider"].as_str().unwrap_or("");
        let local = matches!(provider, "yougoriOci" | "yougoriCuda")
            && !env["runtime"]
                .as_str()
                .is_some_and(|s| s.starts_with("cloud://") || s.starts_with("shared://"));
        let cpu = env["resourcePolicy"]["cpu"]["preferred"].as_f64();
        let memory = env["resourcePolicy"]["memoryGb"]["preferred"].as_f64();
        let mut details = vec![clean(env["runtime"].as_str().unwrap_or("Guest shell"))];
        if let Some(cpu) = cpu {
            details.push(format!("{cpu} CPU"));
        }
        if let Some(memory) = memory {
            details.push(format!("{memory} GB memory"));
        }
        Self {
            id: env["id"].as_str().unwrap_or("").into(),
            name: clean(env["name"].as_str().unwrap_or("Environment")),
            local_shell: local,
            installable: local && env["networkAccess"] != false,
            sandbox_controls: crate::sandbox_stop::is_local_sandbox(env),
            details: details.join(" · "),
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

    pub async fn menu(&self, input: &mut InputReader) -> Result<(), String> {
        let _screen = MenuScreen::enter()?;
        loop {
            let choice = select(
                input,
                &format!("Yougori · {}", self.name),
                &[
                    "Back to shell",
                    "Install a tool",
                    "Share this environment",
                    "Manage sharing",
                    "Show terminal help",
                ],
            )?;
            let action = match choice {
                Some(1) => self.install(input).await,
                Some(2) => self.share(input).await,
                Some(3) => self.shares(input).await,
                Some(4) => {
                    self.help()?;
                    Ok(())
                }
                _ => return Ok(()),
            };
            if let Err(error) = action {
                line(&paint(&clean(&error), "33"))?;
            }
            line("Press Enter to return to the menu, or Esc to return to the shell.")?;
            if prompt(input, "", false)?.is_none() {
                return Ok(());
            }
        }
    }

    fn help(&self) -> Result<(), String> {
        line(if self.sandbox_controls {"Ctrl+C opens Cancel / Stop sandbox / Stop and delete. Cancel returns without interrupting the guest."}
            else {"Ctrl+C interrupts a command inside this environment."})?;
        line("Ctrl+D at an empty shell prompt, exit, or Ctrl+] returns to your PC terminal.")?;
        line("Ctrl+G opens tools and sharing at the shell. Full-screen apps keep their own Ctrl+G shortcut.")?;
        line(&format!(
            "Reconnect: {}",
            shell_words::join(["yougori", "terminal", &self.id])
        ))?;
        line("Installers run in their own shell inside this environment. Its current shell stays open.")
    }

    async fn install(&self, input: &mut InputReader) -> Result<(), String> {
        if !self.installable {
            return Err(
                "Tool installers need a local container with Internet access enabled.".into(),
            );
        }
        let mut choices = vec!["Back"];
        choices.extend(crate::container_tools::TOOLS.iter().copied());
        let Some(index) = select(input, "Install into this environment", &choices)? else {
            return Ok(());
        };
        if index == 0 {
            return Ok(());
        }
        let tool = choices[index];
        line(&format!(
            "Installing {tool} in {}. Sign in inside the container when you launch it.",
            self.name
        ))?;
        // A separate owned PTY cannot inject an installer into a busy shell.
        // The tool launcher checks/install the binary and verifies --version.
        let result = Box::pin(super::attach_tool(&self.id, tool, &["--version".into()])).await;
        // attach_tool restores terminal modes on exit; reenter the host menu.
        print!("\x1b[?1049h\x1b[2J\x1b[H");
        result?;
        line(&format!(
            "{tool} is ready. Run {tool} in the shell, or reconnect with:"
        ))?;
        line(&shell_words::join([
            "yougori",
            tool,
            "--environment",
            &self.id,
        ]))
    }

    async fn share(&self, input: &mut InputReader) -> Result<(), String> {
        let Some(permission) = select(
            input,
            "Recipient access",
            &[
                "Back",
                "View a folder",
                "Edit a folder",
                "Full control of this environment",
            ],
        )?
        else {
            return Ok(());
        };
        if permission == 0 {
            return Ok(());
        }
        let folder = if permission < 3 {
            let Some(folder) = prompt(
                input,
                "Folder to share (absolute guest path, e.g. /workspace): ",
                false,
            )?
            else {
                return Ok(());
            };
            if !folder.starts_with('/') || folder == "/" {
                return Err("Choose a specific absolute folder inside the environment.".into());
            }
            Some(folder)
        } else {
            None
        };
        let Some(username) = prompt(input, "Recipient username: ", false)? else {
            return Ok(());
        };
        let username = username.to_ascii_lowercase();
        if username.is_empty()
            || username.len() > 64
            || !username
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        {
            return Err(
                "Use 1–64 letters, numbers, dots, underscores or hyphens for the username.".into(),
            );
        }
        let Some(password) = prompt(input, "Password (8–256 bytes, hidden): ", true)? else {
            return Ok(());
        };
        let password = Zeroizing::new(password);
        if !(8..=256).contains(&password.len()) {
            return Err("Use a password between 8 and 256 bytes.".into());
        }
        let Some(expiry) = select(
            input,
            "Access expires after",
            &["Cancel", "1 hour", "24 hours", "7 days"],
        )?
        else {
            return Ok(());
        };
        let seconds = match expiry {
            1 => 3600,
            2 => 86400,
            3 => 604800,
            _ => return Ok(()),
        };
        let mode = ["", "view", "edit", "control"][permission];
        line(&format!(
            "Share {} with {username} · {mode} · {} · expires in {} hours",
            self.name,
            folder.as_deref().unwrap_or("whole environment"),
            seconds / 3600
        ))?;
        if permission == 3 {
            line("Full control allows guest commands, files and lifecycle operations, including access already connected to this environment.")?;
        }
        line("This creates password-protected public access. Existing active recipients on the remote gateway can also become reachable.")?;
        if select(
            input,
            "Create recipient and enable sharing?",
            &["Cancel", "Share environment"],
        )? != Some(1)
        {
            return Ok(());
        }
        let request = json!({"targetId":self.id,"username":username,"password":password.as_str(),"permission":mode,
            "folder":folder,"expiresAt":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() + seconds,
            "acknowledgeExistingAccess":permission == 3});
        line("Creating recipient…")?;
        let created = call("create_remote_share", json!({"request":request})).await?;
        let share_id = created["id"]
            .as_str()
            .ok_or("Sharing returned no recipient ID")?;
        line("Enabling the protected sharing gateway…")?;
        match call("start_remote_tunnel", json!({})).await {
            Ok(tunnel) => {
                let url = tunnel["url"]
                    .as_str()
                    .ok_or("The sharing gateway returned no address")?;
                line(&format!("Share link: {url}/share/{share_id}"))?;
                line(&format!("Username: {username}"))?;
                line("Send the password separately. Use Manage sharing to revoke this recipient.")
            }
            Err(error) => {
                // Creating a recipient is a completed effect. Retain its ID and
                // report the partial result; never create another on a retry.
                line(&format!(
                    "Recipient {share_id} was created. The public gateway could not start: {}",
                    clean(&error)
                ))?;
                line("Use Manage sharing → Enable gateway to retry, or revoke this recipient.")
            }
        }
    }

    async fn shares(&self, input: &mut InputReader) -> Result<(), String> {
        let listing = call("list_remote_shares", json!({})).await?;
        let shares: Vec<_> = listing["grants"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|grant| grant["targetId"] == self.id)
            .collect();
        let mut labels = vec![
            "Back".to_owned(),
            "Enable gateway for existing recipients".into(),
        ];
        for grant in &shares {
            labels.push(format!(
                "{} · {} · {}",
                clean(grant["username"].as_str().unwrap_or("Recipient")),
                clean(grant["permission"].as_str().unwrap_or("")),
                clean(grant["status"].as_str().unwrap_or(""))
            ));
        }
        let labels: Vec<_> = labels.iter().map(String::as_str).collect();
        let Some(index) = select(input, "Manage this environment's sharing", &labels)? else {
            return Ok(());
        };
        if index == 0 {
            return Ok(());
        }
        if index == 1 {
            if !shares
                .iter()
                .any(|g| matches!(g["status"].as_str(), Some("online" | "offline")))
            {
                return Err("This environment has no active recipients. Create one with Share this environment first.".into());
            }
            line("Enabling the gateway makes all its active recipients reachable.")?;
            if select(
                input,
                "Enable public sharing gateway?",
                &["Cancel", "Enable gateway"],
            )? == Some(1)
            {
                let result = call("start_remote_tunnel", json!({})).await?;
                line(&format!(
                    "Gateway: {}",
                    clean(result["url"].as_str().unwrap_or(""))
                ))?;
            }
            return Ok(());
        }
        let grant = shares[index - 2];
        if let Some(link) = grant["link"].as_str() {
            line(&format!("Share link: {link}"))?;
        }
        line(&format!(
            "Recipient: {}",
            clean(grant["username"].as_str().unwrap_or(""))
        ))?;
        if select(
            input,
            "Revoke this recipient's access?",
            &["Keep access", "Revoke access"],
        )? == Some(1)
        {
            call(
                "update_remote_share",
                json!({"shareId":grant["id"],"revoke":true}),
            )
            .await?;
            line("Recipient access revoked.")?;
        }
        Ok(())
    }
}

struct MenuScreen;
impl MenuScreen {
    fn enter() -> Result<Self, String> {
        print!("\x1b[?1049h\x1b[2J\x1b[H");
        io::stdout().flush().map_err(|e| e.to_string())?;
        Ok(Self)
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
impl Drop for MenuScreen {
    fn drop(&mut self) {
        print!("\x1b[0m\x1b[?25h\x1b[?1049l");
        let _ = io::stdout().flush();
    }
}

fn select(input: &mut InputReader, title: &str, choices: &[&str]) -> Result<Option<usize>, String> {
    line(&paint(&clean(title), "1;36"))?;
    for (index, choice) in choices.iter().enumerate() {
        line(&format!("  {index}  {}", clean(choice)))?;
    }
    loop {
        let Some(value) = prompt(
            input,
            "Choose a number · Enter for Back · Esc cancels: ",
            false,
        )?
        else {
            return Ok(None);
        };
        if value.is_empty() {
            return Ok(Some(0));
        }
        if let Ok(index) = value.parse::<usize>() {
            if index < choices.len() {
                return Ok(Some(index));
            }
        }
        line("Choose one of the numbers above.")?;
    }
}

fn prompt(input: &mut InputReader, label: &str, secret: bool) -> Result<Option<String>, String> {
    print!("\r\n{label}");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        let batch = input.read_batch()?;
        if batch.detached {
            return Ok(None);
        }
        let mut dirty = batch.resize.is_some();
        for byte in batch.bytes {
            match byte {
                3 | 4 | 7 | 27 => {
                    line("Cancelled.")?;
                    return Ok(None);
                }
                10 | 13 => {
                    line("")?;
                    let value =
                        String::from_utf8(bytes.to_vec()).map_err(|_| "Enter valid UTF-8 text")?;
                    return Ok(Some(value));
                }
                8 | 127 => {
                    if !bytes.is_empty() {
                        bytes.pop();
                        while std::str::from_utf8(&bytes).is_err() {
                            bytes.pop();
                        }
                        dirty = true;
                    }
                }
                32..=255 if bytes.len() < 1024 => {
                    bytes.push(byte);
                    dirty = true;
                }
                _ => {}
            }
        }
        if !secret && dirty {
            print!("\r\x1b[2K{label}{}", String::from_utf8_lossy(&bytes));
            io::stdout().flush().map_err(|e| e.to_string())?;
        }
        std::thread::sleep(Duration::from_millis(20));
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
}
