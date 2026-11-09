//! An independent interactive shell, using the same environment PTY as the app.
use crate::public::call;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crossterm::{event::{KeyCode, KeyEvent, KeyModifiers}, terminal};
#[cfg(not(windows))]
use crossterm::event::{self, Event, KeyEventKind};
#[cfg(windows)]
mod windows_input;
use serde_json::json;
use std::{
    io::{self, IsTerminal, Write},
    process::Command,
    sync::{atomic::{AtomicBool, Ordering}, Arc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
mod ui;
mod tool_setup;
mod transport;
mod ollama;

pub const USAGE: &str = "Usage: yougori terminal ENV [--project] [--container NAME] [--new-window]\n       yougori terminal ENV --subscription TOOL [--new-signin] [--new-window]";

pub(crate) async fn open_ollama(id: &str,name: &str) -> Result<SessionExit,String> {
    ollama::open(id,name).await
}

fn project_command(container: Option<&str>) -> String {
    let command = "cd /workspace && { if [ -f /yougori/venv/bin/activate ]; then . /yougori/venv/bin/activate; fi; if [ -x /bin/bash ]; then exec /bin/bash -i; else exec /bin/sh -i; fi; }";
    match container {
        Some(name) => format!(
            "exec docker exec -it -w /workspace {} sh -c {}",
            shell_words::quote(name),
            shell_words::quote(command)
        ),
        None => command.into(),
    }
}

/// Open a visible terminal without borrowing the calling command's stdin.
pub fn open(environment: &str, project: bool, container: Option<&str>) -> Result<(), String> {
    let mut args = vec![
        "terminal".to_owned(),
        environment.to_owned(),
        "--window".into(),
    ];
    if project {
        args.push("--project".into());
    }
    if let Some(name) = container {
        args.extend(["--container".into(), name.into()]);
    }
    open_window(&args)
}

fn subscription_arguments(environment: &str, tool: &str, new_signin: bool, window_flag: &str) -> Result<Vec<String>, String> {
    subscription_command(tool, &[])?;
    let mut args = vec!["terminal".into(), environment.into(), "--subscription".into(), tool.into(), window_flag.into()];
    if new_signin { args.push("--new-signin".into()); }
    Ok(args)
}

pub(crate) fn subscription_reopen_command(environment: &str, tool: &str, new_signin: bool) -> Result<String, String> {
    Ok(shell_words::join(std::iter::once("yougori".into()).chain(subscription_arguments(environment, tool, new_signin, "--new-window")?)))
}

/// The Hub keeps its own keyboard and screen. No provider process inherits them.
pub(crate) fn open_subscription(environment: &str, tool: &str, new_signin: bool) -> Result<(), String> {
    open_window(&subscription_arguments(environment, tool, new_signin, "--window")?)
}

fn open_window(args: &[String]) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // This is explicitly requested interactive UI. Create its own console and
        // standard handles rather than inheriting the raw project/chat terminal.
        let child = Command::new(exe)
            .args(args)
            .creation_flags(0x00000010)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("Could not open terminal: {e}"))?;
        std::thread::spawn(move || {
            let mut child = child;
            let _ = child.wait();
        });
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let line =
            shell_words::join(std::iter::once(exe.to_string_lossy().into_owned()).chain(args.iter().cloned()));
        // AppleScript receives a string literal; the shell receives quoted argv.
        let literal = format!("\"{}\"", line.replace('\\', "\\\\").replace('"', "\\\""));
        let status = Command::new("osascript")
            .args([
                "-e",
                &format!("tell application \"Terminal\"\nactivate\ndo script {literal}\nend tell"),
            ])
            .status()
            .map_err(|e| format!("Could not open Terminal: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err("Terminal could not open the environment shell".into())
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for (program, flag) in [
            ("x-terminal-emulator", "-e"),
            ("gnome-terminal", "--"),
            ("konsole", "-e"),
            ("xterm", "-e"),
        ] {
            match Command::new(program)
                .arg(flag)
                .arg(&exe)
                .args(args)
                .spawn()
            {
                Ok(mut child) => {
                    std::thread::spawn(move || {
                        let _ = child.wait();
                    });
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("Could not open terminal: {error}")),
            }
        }
        Err(format!(
            "No desktop terminal found. Open another terminal and run: {}",
            shell_words::join(std::iter::once(exe.to_string_lossy().into_owned()).chain(args.iter().cloned()))
        ))
    }
}

/// Binds standard input, output and error to this process's own console window. A process
/// started with a new console and null inherited streams (as [`open`] starts a terminal, and as
/// the app starts Hub commands) reads and writes that window from here on, never the starter's
/// handles. Elsewhere there is nothing to do.
pub fn attach_console() -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::{fs::OpenOptions, os::windows::io::IntoRawHandle};
        use windows_sys::Win32::System::Console::{
            SetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };
        for (device, handle) in [
            ("CONIN$", STD_INPUT_HANDLE),
            ("CONOUT$", STD_OUTPUT_HANDLE),
            ("CONOUT$", STD_ERROR_HANDLE),
        ] {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(device)
                .map_err(|e| e.to_string())?;
            if unsafe { SetStdHandle(handle, file.into_raw_handle()) } == 0 {
                return Err(io::Error::last_os_error().to_string());
            }
        }
    }
    Ok(())
}

pub async fn run(args: &[String]) -> Result<(), String> {
    let window = args.iter().any(|s| s == "--window");
    // NEW_CONSOLE with null inherited streams: attach explicitly to the new
    // console, never to the calling command's input or output handles.
    if window {
        attach_console()?;
    }
    let result = run_inner(args).await;
    if window {
        if let Err(error) = &result {
            eprintln!(
                "Could not open the environment shell: {error}\nPress Enter to close this window."
            );
            let _ = io::stdin().read_line(&mut String::new());
        } else if args.iter().any(|arg| arg == "--subscription") {
            println!("Sign-in terminal closed. Your setup continues in the original window.\nPress Enter to close this window.");
            let _ = io::stdin().read_line(&mut String::new());
        }
    }
    result
}

#[derive(Debug, PartialEq)]
struct TerminalOptions<'a> {
    target: &'a str,
    project: bool,
    container: Option<&'a str>,
    subscription: Option<&'a str>,
    new_signin: bool,
    new_window: bool,
}

fn options(args: &[String]) -> Result<TerminalOptions<'_>, String> {
    let target = args
        .get(1)
        .filter(|s| !s.starts_with('-'))
        .ok_or(USAGE)?;
    let mut project = false;
    let mut container = None;
    let mut subscription = None;
    let mut new_signin = false;
    let mut new_window = false;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--window" => {}
            "--project" => project = true,
            "--new-window" => new_window = true,
            "--new-signin" => new_signin = true,
            "--subscription" if subscription.is_none() => {
                i += 1;
                let tool = args.get(i).ok_or("--subscription needs a tool name.")?;
                subscription_command(tool, &[])?;
                subscription = Some(tool.as_str());
            }
            "--container" if container.is_none() => {
                i += 1;
                let name = args.get(i).ok_or("--container needs a value: the container's name.")?;
                if name.is_empty() || name.starts_with('-') || name.chars().any(char::is_control) {
                    return Err("--container must be a container name, without a leading dash or control characters.".into());
                }
                container = Some(name.as_str());
                project = true;
            }
            other => return Err(format!("Unknown option {other} for yougori terminal. {USAGE}")),
        }
        i += 1;
    }
    if subscription.is_some() && project {
        return Err("--subscription cannot be combined with --project or --container.".into());
    }
    if new_signin && subscription.is_none() {
        return Err("--new-signin requires --subscription TOOL.".into());
    }
    if new_window && args.iter().any(|arg| arg == "--window") {
        return Err("--new-window cannot be combined with --window.".into());
    }
    Ok(TerminalOptions { target, project, container, subscription, new_signin, new_window })
}

async fn run_inner(args: &[String]) -> Result<(), String> {
    let TerminalOptions { target, project, container, subscription, new_signin, new_window } = options(args)?;
    if new_window {
        return match subscription {
            Some(tool) => open_subscription(target, tool, new_signin),
            None => open(target, project, container),
        };
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("yougori terminal needs an interactive terminal. For scripts use yougori exec or yougori terminal create.".into());
    }
    crate::client::start(None).await?;
    let id = crate::public::resolve(target).await?;
    if let Some(tool) = subscription {
        crossterm::execute!(io::stdout(), crossterm::terminal::SetTitle(format!("Yougori - {tool} sign-in"))).map_err(|e| e.to_string())?;
        println!("{tool} sign-in\nYour setup is still in the original window. You can close this window when finished.");
        if new_signin && tool == "gemini" { println!("In Gemini, use /auth to choose the new Google account."); }
        return attach_subscription_tool(&id, tool, &subscription_login_arguments(tool, new_signin)).await.map(|_| ());
    }
    attach(&id, project.then(|| project_command(container)).as_deref()).await
}

struct Raw(bool);
impl Drop for Raw {
    fn drop(&mut self) {
        if !self.0 {
            let _ = terminal::disable_raw_mode();
        }
    }
}

fn key_bytes(key: KeyEvent) -> Vec<u8> {
    let control = key.modifiers.contains(KeyModifiers::CONTROL);
    // xterm's modifier parameter for keys that carry one: 1, plus 1 for Shift, 2 for Alt, 4 for Ctrl.
    let modifier = 1 + u8::from(key.modifiers.contains(KeyModifiers::SHIFT)) + 2 * u8::from(key.modifiers.contains(KeyModifiers::ALT)) + 4 * u8::from(control);
    let cursor = |letter: char| if modifier > 1 { format!("\x1b[1;{modifier}{letter}") } else { format!("\x1b[{letter}") }.into_bytes();
    let tilde = |number: u8| if modifier > 1 { format!("\x1b[{number};{modifier}~") } else { format!("\x1b[{number}~") }.into_bytes();
    let function = |letter: char| if modifier > 1 { format!("\x1b[1;{modifier}{letter}") } else { format!("\x1bO{letter}") }.into_bytes();
    let (mut bytes, carries_modifier) = match key.code {
        // Unix terminals send Ctrl+\, Ctrl+], Ctrl+^ and Ctrl+_ as 0x1c-0x1f, which crossterm reads
        // as Ctrl+4 to Ctrl+7; masking the digit would send Ctrl+T, Ctrl+U, Ctrl+V and Ctrl+W.
        KeyCode::Char(c @ '4'..='7') if control => (vec![0x1c + (c as u8 - b'4')], false),
        KeyCode::Char(c) if control && c.is_ascii() => (vec![(c.to_ascii_lowercase() as u8) & 0x1f], false),
        KeyCode::Char(c) => (c.to_string().into_bytes(), false),
        KeyCode::Enter => (vec![13], false),
        KeyCode::Backspace => (vec![127], false),
        KeyCode::Tab => (vec![9], false),
        KeyCode::Esc => (vec![27], false),
        KeyCode::Up => (cursor('A'), true),
        KeyCode::Down => (cursor('B'), true),
        KeyCode::Right => (cursor('C'), true),
        KeyCode::Left => (cursor('D'), true),
        KeyCode::Home => (cursor('H'), true),
        KeyCode::End => (cursor('F'), true),
        KeyCode::Insert => (tilde(2), true),
        KeyCode::Delete => (tilde(3), true),
        KeyCode::PageUp => (tilde(5), true),
        KeyCode::PageDown => (tilde(6), true),
        KeyCode::BackTab => (b"\x1b[Z".to_vec(), true),
        KeyCode::F(number @ 1..=4) => (function(['P', 'Q', 'R', 'S'][usize::from(number) - 1]), true),
        KeyCode::F(number @ 5..=12) => (tilde([15, 17, 18, 19, 20, 21, 23, 24][usize::from(number) - 5]), true),
        _ => (vec![], false),
    };
    // Alt before a plain key is ESC first; a key with a modifier parameter carries Alt in it.
    if key.modifiers.contains(KeyModifiers::ALT) && !carries_modifier && !bytes.is_empty() {
        bytes.insert(0, 27);
    }
    bytes
}

/// The most guest output held while a host menu is open; past it the session catches up by reconnecting.
const HELD_OUTPUT_LIMIT: usize = 256 * 1024 * 1024;

/// Runs a host menu (its prompts block) on a thread of its own while this session keeps taking
/// the guest's output and holds it, not drawn over the menu. A guest that keeps printing never
/// fills the pipe, so the engine's writer never stalls and closes the session (after 15 seconds)
/// while the person reads the menu. The held output is drawn when the menu closes.
async fn hold_output_while<T: Send + 'static>(
    menu: impl FnOnce() -> Result<T, String> + Send + 'static,
    rx: &mut tokio::sync::mpsc::Receiver<Result<crate::terminal_stream::Frame, String>>,
    held: &mut std::collections::VecDeque<Option<Result<crate::terminal_stream::Frame, String>>>,
) -> Result<T, String> {
    let (done, mut finished) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("yougori-terminal-menu".into())
        .spawn(move || { let _ = done.send(menu()); })
        .map_err(|error| format!("The menu could not open: {error}"))?;
    let ended = || Err::<T, String>("The menu ended unexpectedly".into());
    let mut bytes = 0_usize;
    loop {
        tokio::select! {
            result = &mut finished => return result.unwrap_or_else(|_| ended()),
            frame = rx.recv(), if bytes <= HELD_OUTPUT_LIMIT => {
                if let Some(Ok(crate::terminal_stream::Frame::Output { bytes: output, .. })) = &frame { bytes += output.len(); }
                let open = matches!(frame, Some(Ok(_)));
                held.push_back(frame);
                // The connection ended: the menu still finishes, and the session reports it then.
                if !open { return finished.await.unwrap_or_else(|_| ended()); }
            }
        }
    }
}

fn detach_key(key: KeyEvent) -> bool {
    if !key.modifiers.contains(KeyModifiers::CONTROL) {
        return false;
    }
    if key.code == KeyCode::Char(']') {
        return true;
    }
    // Unix terminals send the byte 0x1d for Ctrl+]. Crossterm decodes that
    // legacy control byte as Ctrl+5; Windows console events retain Ctrl+].
    #[cfg(unix)]
    if key.code == KeyCode::Char('5') {
        return true;
    }
    false
}

#[derive(Default)]
struct InputBatch { bytes: Vec<u8>, resize: Option<(u16, u16)>, detached: bool, pasted: bool }

#[cfg(not(windows))]
#[derive(Default)]
struct InputReader;
#[cfg(windows)]
use windows_input::InputReader;

#[cfg(not(windows))]
impl InputReader {
    fn read_batch(&mut self) -> Result<InputBatch, String> {
        let mut batch = InputBatch::default();
        while event::poll(Duration::from_millis(1)).map_err(|e| e.to_string())? {
            match event::read().map_err(|e| e.to_string())? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    if detach_key(key) { batch.detached = true; break; }
                    batch.bytes.extend(key_bytes(key));
                }
                Event::Paste(text) => { batch.pasted = true; batch.bytes.extend(text.into_bytes()); },
                Event::Resize(cols, rows) => batch.resize = Some((cols, rows)),
                _ => {},
            }
            if batch.bytes.len() >= 64 * 1024 { break; }
        }
        Ok(batch)
    }
}

pub async fn attach(id: &str, command: Option<&str>) -> Result<(), String> {
    attach_session(id, command, None).await.map(|_| ())
}

pub async fn attach_tool(id: &str, tool: &str, arguments: &[String]) -> Result<(), String> {
    attach_tool_session(id, tool, arguments).await.map(|_| ())
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum SessionExit { Completed, Detached, Stopped }

pub(crate) async fn attach_tool_session(id: &str, tool: &str, arguments: &[String]) -> Result<SessionExit, String> {
    if !crate::container_tools::TOOLS.contains(&tool) { return Err("Unknown tool".into()); }
    let setup = setup_tool(id, tool).await?;
    if setup != SessionExit::Completed || arguments == ["--version"] { return Ok(setup); }
    attach_prepared_tool(id, tool, arguments).await
}

pub(crate) async fn attach_prepared_tool(id: &str, tool: &str, arguments: &[String]) -> Result<SessionExit, String> {
    if !crate::container_tools::TOOLS.contains(&tool) { return Err("Unknown tool".into()); }
    if arguments == ["--version"] { return Ok(SessionExit::Completed); }
    attach_session(id, None, Some((tool, arguments))).await
}

/// A subscription terminal must not silently pick up the API bridge's billing credentials.
/// This changes only the terminal's child process; the bridge keeps its protected bindings.
fn subscription_command(tool: &str, arguments: &[String]) -> Result<String, String> {
    let variables = match tool {
        "codex" => "OPENAI_API_KEY",
        "claude" => "ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN",
        "gemini" => "GEMINI_API_KEY GOOGLE_API_KEY GOOGLE_GENAI_USE_VERTEXAI",
        "opencode" => "OPENCODE_API_KEY",
        "kilo" => "KILO_API_KEY",
        _ => return Err("This tool has no subscription sign-in flow.".into()),
    };
    let launch = shell_words::join(std::iter::once(tool.to_owned()).chain(arguments.iter().cloned()));
    Ok(format!("export PATH=\"$HOME/.local/share/yougori/bin:$HOME/.local/bin:$PATH\"; {TOOL_ENV}; unset {variables}; mkdir -p /workspace; cd /workspace && exec {launch}"))
}

pub(crate) async fn attach_subscription_tool(id: &str, tool: &str, arguments: &[String]) -> Result<SessionExit, String> {
    attach_session(id, Some(&subscription_command(tool, arguments)?), None).await
}

fn subscription_login_arguments(tool: &str, new_signin: bool) -> Vec<String> {
    if !new_signin { return crate::container_tools::launch_arguments(tool, &[]); }
    match tool {
        "codex" => vec!["login".into(), "--device-auth".into()],
        "claude" => vec!["auth".into(), "login".into(), "--claudeai".into()],
        "opencode" | "kilo" => vec!["auth".into(), "login".into()],
        _ => crate::container_tools::launch_arguments(tool, &[]),
    }
}

/// A connection that dropped, said the same way however it dropped, with what to do next. Its
/// code is attached here: what was typed may or may not have arrived, which a program needs to
/// know whatever words this uses.
fn connection_lost(name: &str, why: &str, next: &str) -> String {
    crate::client::remember_error(
        format!("The connection to {name} ended ({why}), so anything typed since may not have arrived. {next}"),
        crate::wire::ErrorDetails::of(crate::wire::Code::OutcomeUnknown),
    )
}

/// Where to look and how to try again after a tool's setup in this sandbox did not finish.
pub(crate) async fn retry_steps(id: &str, tool: &str) -> String {
    let state = call("get_platform_state", json!({})).await.unwrap_or_default();
    let environments = state["environments"].as_array().map_or(&[][..], Vec::as_slice);
    format!(
        "Look inside with {}, then run {} to try again.",
        shell_words::join(["yougori", "terminal", &crate::container_tools::handle(environments, id)]),
        crate::container_tools::reconnect_command(tool, id, environments),
    )
}

pub(crate) async fn setup_tool(id: &str, tool: &str) -> Result<SessionExit, String> {
    tool_setup::ensure(id, tool).await
}

/// [`setup_tool`] inside a Hub run, where Ctrl+C stops the run rather than the sandbox.
pub(crate) async fn setup_tool_in_run(id: &str, tool: &str) -> Result<SessionExit, String> {
    tool_setup::ensure_in_run(id, tool).await
}

pub(crate) async fn tool_ready(id: &str, tool: &str) -> Result<bool, String> {
    if !crate::container_tools::TOOLS.contains(&tool) { return Err("Unknown tool".into()); }
    let probe = call("execute_environment_command", json!({"request":{"environmentId":id,"command":format!("{TOOL_ENV}; if command -v {tool} >/dev/null 2>&1; then printf ready; else printf missing; fi")}})).await?;
    if probe["exitCode"] != 0 { return Err("Could not check the tool inside this sandbox".into()); }
    match probe["stdout"].as_str().unwrap_or("").trim() {
        "ready" => Ok(true),
        "missing" => Ok(false),
        _ => Err("The tool check returned an unexpected result".into()),
    }
}

const TOOL_ENV: &str = "[ ! -r \"$HOME/.local/share/yougori/tool-env.sh\" ] || . \"$HOME/.local/share/yougori/tool-env.sh\"";

pub(crate) fn shared_tool_shell() -> String {
    format!("export PATH=\"$HOME/.local/share/yougori/bin:$HOME/.local/bin:$PATH\"; {TOOL_ENV}; cd /workspace && {{ if [ -x /bin/bash ]; then exec /bin/bash -i; else exec /bin/sh -i; fi; }}")
}

fn tool_command(tool: &str, arguments: &[String], status: &str) -> Result<String, String> {
    let launch = shell_words::join(std::iter::once(tool.to_owned()).chain(arguments.iter().cloned()));
    let cleanup = format!("od_status=$?; rm -f {}; printf '%s\\n' \"$od_status\" > {}; exit \"$od_status\"", shell_words::quote(&format!("{status}.sh")), shell_words::quote(status));
    let script = format!("umask 077; trap {} EXIT; set -e; {TOOL_ENV}; mkdir -p /workspace; cd /workspace; {launch}", shell_words::quote(&cleanup));
    Ok(format!("exec sh -c {}", shell_words::quote(&script)))
}

fn installer_path(installer: &str) -> Result<String, String> {
    let parts = shell_words::split(installer).map_err(|_| "Invalid installer launcher")?;
    let path = parts.get(2).ok_or("Invalid installer launcher")?;
    let suffix = path.strip_prefix("/tmp/yougori-install.").and_then(|value| value.strip_suffix("/install.sh")).ok_or("Invalid installer launcher")?;
    if parts.len() != 3 || parts[0] != "exec" || parts[1] != "sh" || suffix.is_empty() || suffix.len() > 32 || !suffix.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("Invalid installer launcher".into());
    }
    Ok(path.clone())
}

/// A shell that is set up and ready to take over the terminal.
struct Opened {
    context: ui::Context,
    sandbox_controls: bool,
    launch: Option<String>,
    offset: u64,
    /// The shell's first output, its prompt, which arrived while it was set up.
    early: Vec<u8>,
    stream: crate::terminal_stream::Channel,
    open_elapsed: Duration,
}

/// Stops a wait with [`crate::cli_ui::CANCELLED`] once Ctrl+C was pressed.
fn stop_if(cancelled: &AtomicBool) -> Result<(), String> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(crate::cli_ui::CANCELLED.into());
    }
    Ok(())
}

/// Waits for `work` unless Ctrl+C was pressed meanwhile; then it stops waiting at once.
async fn unless_cancelled<T>(cancelled: &AtomicBool, work: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
    let mut work = std::pin::pin!(work);
    loop {
        stop_if(cancelled)?;
        tokio::select! {
            result = &mut work => return result,
            _ = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
    }
}

/// Sets the shell up behind a spinner, before the guest gets the keyboard, so the screen never
/// sits blank and Ctrl+C stops the wait. A terminal the engine already created is closed again,
/// so a cancelled open leaves nothing running, says so, and ends as a cancellation.
async fn open_session(
    id: &str,
    session: &str,
    command: Option<&str>,
    tool: Option<(&str, &[String])>,
    status: &str,
    (cols, rows): (u16, u16),
) -> Result<Opened, String> {
    use crate::cli_ui as kit;
    let cancelled = Arc::new(AtomicBool::new(false));
    let _keys = kit::Interrupts::watch(cancelled.clone());
    let mut task = kit::task(&match tool {
        Some((tool, _)) => format!("Opening {tool}"),
        None => "Opening the shell".to_owned(),
    });
    let mut created = false;
    let mut name = "The environment".to_owned();
    let opened = async {
        let state = unless_cancelled(&cancelled, call("get_platform_state", json!({}))).await?;
        let environments = state["environments"].as_array().map_or(&[][..], Vec::as_slice);
        let environment = environments
            .iter()
            .find(|item| item["id"] == id)
            .ok_or("This environment was not found. See your environments with yougori ps.")?;
        let context = ui::Context::new(environment, environments);
        name = context.name.clone();
        task.set(&match tool {
            Some((tool, _)) => format!("Opening {tool} in {name}"),
            None => format!("Opening a shell in {name}"),
        });
        // Not raced with Ctrl+C: a terminal the engine is creating is waited for, so it can be
        // closed again.
        call(
            "terminal_action",
            json!({"environmentId":id,"sessionId":session,"action":"create","cols":cols,"rows":rows}),
        )
        .await?;
        created = true;
        stop_if(&cancelled)?;
        let launch = if let Some((tool, arguments)) = tool {
            // Tool setup completed in its separate quiet PTY. Only the running
            // tool owns this visible terminal; package output never reaches it.
            let command = tool_command(tool, arguments, status)?;
            let script = shell_words::split(&command).map_err(|_| "Invalid tool launcher")?.pop().ok_or("Missing tool launcher")?;
            let path = format!("{status}.sh");
            let staged = unless_cancelled(&cancelled, call("execute_environment_command", json!({"request":{"environmentId":id,"command":format!("umask 077; printf %s {} > {}",shell_words::quote(&script),shell_words::quote(&path))}}))).await?;
            if staged["exitCode"] != 0 { return Err("Could not stage the tool launcher inside this sandbox".into()); }
            Some(format!("exec sh {}", shell_words::quote(&path)))
        } else { command.map(str::to_owned) };
        let mut offset = 0;
        let mut early = Vec::new();
        if launch.is_none() && context.local_shell {
            // Set a session-only prompt, and consume the echoed setup command.
            // The marker is split in the command so its echo cannot match it.
            let marker = format!("yougori-ready-{session}");
            let setup = ui::shell_setup(&context.name, &marker);
            unless_cancelled(&cancelled, call("terminal_action", json!({"environmentId":id,"sessionId":session,"action":"write","data":B64.encode(format!("{setup}\r"))}))).await?;
            let mut pending = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let read = unless_cancelled(&cancelled, call("terminal_action", json!({"environmentId":id,"sessionId":session,"action":"read","offset":offset}))).await?;
                pending.extend(B64.decode(read["data"].as_str().unwrap_or("")).map_err(|e| e.to_string())?);
                offset = read["offset"].as_u64().unwrap_or(offset);
                if let Some(position) = pending.windows(marker.len()).position(|bytes| bytes == marker.as_bytes()) {
                    early = pending.split_off(position + marker.len());
                    break;
                }
                if read["done"] == true || pending.len() > 64 * 1024 || Instant::now() >= deadline {
                    early = pending;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        }
        let opening = Instant::now();
        let stream = unless_cancelled(&cancelled, transport::open(id, session, offset)).await?;
        Ok(Opened {
            sandbox_controls: crate::sandbox_stop::is_local_sandbox(environment),
            context,
            launch,
            offset,
            early,
            stream,
            open_elapsed: opening.elapsed(),
        })
    }
    .await;
    task.clear();
    let error = match opened {
        Ok(opened) => return Ok(opened),
        Err(error) => error,
    };
    if created {
        let _ = call("terminal_action", json!({"environmentId":id,"sessionId":session,"action":"close"})).await;
    }
    if error != kit::CANCELLED {
        return Err(error);
    }
    kit::outro(&kit::muted(&match tool {
        Some((tool, _)) => format!("Cancelled. {tool} was not opened, and {name} keeps running."),
        None => format!("Cancelled. The shell was not opened, and {name} keeps running."),
    }));
    Err(crate::wire::cancelled(""))
}

async fn attach_session(id: &str, command: Option<&str>, tool: Option<(&str, &[String])>) -> Result<SessionExit, String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(
            "A shell requires an interactive terminal; the environment is still running".into(),
        );
    }
    let session = format!(
        "term-cli-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let status = format!("/tmp/yougori-tool-{session}.status");
    let (cols, rows) = terminal::size().unwrap_or((100, 30));
    let Opened { context, sandbox_controls, launch, mut offset, early, mut stream, open_elapsed } =
        open_session(id, &session, command, tool, &status, (cols, rows)).await?;
    // The guest owns the keyboard from here, so raw mode starts only now that it is ready.
    let raw = terminal::is_raw_mode_enabled().and_then(|enabled| terminal::enable_raw_mode().map(|()| Raw(enabled)));
    let raw = match raw {
        Ok(raw) => raw,
        Err(error) => {
            let _ = call("terminal_action", json!({"environmentId":id,"sessionId":session,"action":"close"})).await;
            return Err(error.to_string());
        }
    };
    let _painter = crate::cli_ui::Paused::new();
    // However the connection drops, it reads the same, with what to do next. A tool's launch
    // ends with its own line saying how to open it again.
    let next = match tool {
        Some(_) => format!("{} keeps running.", ui::clean(&context.name)),
        None => format!("Reconnect with {}.", shell_words::join(["yougori", "terminal", &context.handle])),
    };
    let lost = |why: &str| connection_lost(&ui::clean(&context.name), why, &next);
    let result = async {
        if tool.is_none() { context.welcome()?; }
        io::stdout().write_all(&early).map_err(|e| e.to_string())?;
        let mut input_reader = InputReader::default();
        let mut interrupts = ui::Interrupts::default();
        let mut screen = ui::GuestScreen::default();
        let mut pending = std::collections::VecDeque::new();
        // The guest's output that arrived while a host menu was open, drawn once it closes.
        let mut held: std::collections::VecDeque<Option<Result<crate::terminal_stream::Frame, String>>> = std::collections::VecDeque::new();
        if let Some(command) = launch {
            for chunk in format!("{command}\r").as_bytes().chunks(12*1024) {
                if pending.len() >= 32 { return Err("Terminal launch command is too large".into()); }
                pending.push_back(crate::terminal_stream::Frame::Input(chunk.to_vec()));
            }
        }
        let mut keyboard = tokio::time::interval(Duration::from_millis(4));
        keyboard.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let started = Instant::now();
        let mut output_bytes = 0_u64;
        let mut input_bytes = 0_u64;
        let exit = loop {
            use crate::terminal_stream::Frame;
            let done = tokio::select! {
                frame = async { match held.pop_front() { Some(frame) => frame, None => stream.rx.recv().await } } => match frame.ok_or_else(|| lost("it closed"))?.map_err(|error| lost(&error))? {
                    Frame::Output { offset: next, bytes } => {
                        if next.checked_sub(bytes.len() as u64) != Some(offset) { return Err(lost("the screen fell out of step")); }
                        offset = next;
                        output_bytes += bytes.len() as u64;
                        screen.feed(&bytes);
                        io::stdout().write_all(&bytes).map_err(|e| e.to_string())?;
                        io::stdout().flush().map_err(|e| e.to_string())?;
                        continue;
                    },
                    Frame::Done => true,
                    Frame::Error(error) => return Err(lost(&error)),
                    _ => return Err(lost("an unexpected reply")),
                },
                permit = stream.tx.reserve(), if !pending.is_empty() => {
                    let frame = pending.pop_front().unwrap();
                    if let Frame::Input(bytes) = &frame { input_bytes += bytes.len() as u64; }
                    permit.map_err(|_| lost("input could not be sent"))?.send(frame);
                    continue;
                },
                _ = keyboard.tick() => false,
            };
            if done {
                if std::env::var_os("YOUGORI_TERMINAL_TRACE").is_some() {
                    eprintln!("Terminal timing: {:.3}s stream opening; {:.3}s attached; {input_bytes} input bytes; {output_bytes} output bytes", open_elapsed.as_secs_f64(), started.elapsed().as_secs_f64());
                }
                if tool.is_some() {
                    let exit = call("execute_environment_command", json!({"request":{"environmentId":id,"command":format!("test -f {0} && cat {0} && rm -f {0}",shell_words::quote(&status))}})).await?;
                    let code = exit["stdout"].as_str().unwrap_or("").trim().parse::<u8>().map_err(|_| "The tool session ended without an exit result. The sandbox and files remain.")?;
                    if code != 0 { return Err(format!("The tool session exited with status {code}. Read its terminal output above; the sandbox and files remain.")); }
                }
                break SessionExit::Completed;
            }
            // Send queued input together. Splitting ESC/control reports across
            // RPC round trips makes full-screen tools treat their tails as text.
            let mut input = input_reader.read_batch()?;
            if input.detached { return Ok(SessionExit::Detached); }
            let actions = if input.pasted { ui::Actions::default() }
                else { ui::filter_input(&mut input.bytes, &mut interrupts, tool.is_none() && !screen.alternate, sandbox_controls) };
            if actions.stop {
                // Nothing from this input batch reaches the guest. In particular
                // Ctrl+C cannot terminate an installer/tool before Cancel resumes it.
                input.bytes.clear();
                let stopped = {
                    let _overlay = ui::StopOverlay::enter(screen.alternate)?;
                    let menu_id = id.to_owned();
                    hold_output_while(move || {
                        tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|error| error.to_string())?
                            .block_on(crate::sandbox_stop::menu(&menu_id))
                    }, &mut stream.rx, &mut held).await
                };
                match stopped {
                    Ok(true) => return Ok(SessionExit::Stopped),
                    Ok(false) => {},
                    Err(error) => return Err(error),
                }
                // Repaint a full-screen tool after restoring its screen. Cancel
                // never closes this PTY or sends an interrupt into it.
                let (cols, rows) = terminal::size().unwrap_or((cols, rows));
                pending.push_back(Frame::Resize(cols.saturating_sub(1).max(1),rows));
                pending.push_back(Frame::Resize(cols,rows));
            }
            if let Some((cols, rows)) = input.resize {
                if matches!(pending.back(),Some(Frame::Resize(_, _))) { pending.pop_back(); }
                pending.push_back(Frame::Resize(cols,rows));
            }
            for chunk in input.bytes.chunks(12 * 1024) {
                if pending.len() >= 32 { return Err(lost("it fell too far behind")); }
                pending.push_back(Frame::Input(chunk.to_vec()));
            }
            if actions.exit_hint {
                ui::line("")?;
                ui::line(if tool.is_some() { "Ctrl+C interrupts the guest tool. Press Ctrl+] to return to your PC terminal; the sandbox and files remain." }
                    else { "Ctrl+C interrupts the guest command. Press Ctrl+D at an empty shell prompt, type exit, or press Ctrl+] to return to your PC terminal." })?;
            }
            if actions.menu {
                let menu_context = context.clone();
                let chosen = hold_output_while(move || {
                    tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|error| error.to_string())?
                        .block_on(menu_context.menu())
                }, &mut stream.rx, &mut held).await;
                if let Err(error) = chosen {
                    ui::line(&format!("Could not complete that action: {}", ui::clean(&error)))?;
                }
                // Redraw full-screen programs/readline after the host menu closes.
                let (cols, rows) = terminal::size().unwrap_or((cols, rows));
                pending.push_back(Frame::Resize(cols,rows));
            }
        };
        Ok(exit)
    }.await;
    // Close only this new PTY. Lifecycle changes require the explicit choices above.
    let _ = call(
        "terminal_action",
        json!({"environmentId":id,"sessionId":session,"action":"close"}),
    )
    .await;
    // A detached full-screen guest program may not send its normal cleanup.
    // Restore the host screen and cursor before returning to a CLI menu.
    let _ = io::stdout().write_all(b"\x1b[?1049l\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l\x1b[?1004l\x1b[<u\x1b[>4;0m\x1b[0 q\x1b[0m\x1b[?25h\r\n");
    let _ = io::stdout().flush();
    drop(raw);
    if result == Ok(SessionExit::Stopped) { println!("Returned to your PC terminal after the sandbox stop action."); }
    else if tool.is_none() && result.is_ok() { println!("Returned to your PC terminal. {} keeps running.", ui::clean(&context.name)); }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    /// PROVES that a dropped connection carries its code whatever it is worded: the words name
    /// the environment between "connection" and "ended", which no reading of the words matched.
    #[tokio::test]
    async fn a_dropped_connection_says_the_outcome_is_unknown_in_any_words() {
        let failed = crate::client::capture_errors(async { Err::<(), _>(connection_lost("web", "it closed", "Reconnect with yougori terminal web.")) }).await.unwrap_err();
        assert_eq!(failed.error.as_deref(), Some("The connection to web ended (it closed), so anything typed since may not have arrived. Reconnect with yougori terminal web."));
        assert_eq!(failed.error_details.unwrap().code, "outcome_unknown");
    }
    #[test]
    fn visible_tool_launcher_preserves_literal_arguments_and_never_runs_installers() {
        let args = vec!["--prompt".into(), "spaces; $(touch /tmp/no) and 'quotes'".into()];
        let command = tool_command("codex", &args, "/tmp/status").unwrap();
        let outer = shell_words::split(&command).unwrap();
        assert_eq!(&outer[..3], &["exec", "sh", "-c"]);
        let script = &outer[3];
        assert!(!script.contains("/install.sh"));
        let tail = script.split("cd /workspace; ").last().unwrap();
        assert_eq!(shell_words::split(tail).unwrap(), [vec!["codex".to_owned()], args].concat());
        assert!(!tool_command("claude", &[], "/tmp/status").unwrap().contains("/install.sh"));
    }
    #[test]
    fn cloud_shell_enters_the_project_container_with_quoted_arguments() {
        let name = "project's container; echo nope";
        let args = shell_words::split(&project_command(Some(name))).unwrap();
        assert_eq!(
            &args[..7],
            &["exec", "docker", "exec", "-it", "-w", "/workspace", name]
        );
        assert_eq!(&args[7..9], &["sh", "-c"]);
        assert_eq!(args[9], project_command(None));
    }
    #[test]
    fn terminal_keys_forward_interrupts_unicode_and_navigation() {
        assert_eq!(
            key_bytes(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            vec![3]
        );
        assert_eq!(
            key_bytes(KeyEvent::new(KeyCode::Char('é'), KeyModifiers::NONE)),
            "é".as_bytes()
        );
        assert_eq!(
            key_bytes(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE)),
            b"\x1b[D"
        );
        assert_eq!(
            key_bytes(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::ALT)),
            b"\x1bb"
        );
        // Unix terminals' Ctrl+\ and Ctrl+_ arrive as Ctrl+4 and Ctrl+7: SIGQUIT and readline undo.
        assert_eq!(key_bytes(KeyEvent::new(KeyCode::Char('4'), KeyModifiers::CONTROL)), vec![0x1c]);
        assert_eq!(key_bytes(KeyEvent::new(KeyCode::Char('7'), KeyModifiers::CONTROL)), vec![0x1f]);
        // Function keys, Insert and modified navigation keys, as xterm sends them.
        assert_eq!(key_bytes(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE)), b"\x1bOP");
        assert_eq!(key_bytes(KeyEvent::new(KeyCode::F(10), KeyModifiers::NONE)), b"\x1b[21~");
        assert_eq!(key_bytes(KeyEvent::new(KeyCode::Insert, KeyModifiers::NONE)), b"\x1b[2~");
        assert_eq!(key_bytes(KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL)), b"\x1b[1;5D");
        assert_eq!(key_bytes(KeyEvent::new(KeyCode::Right, KeyModifiers::SHIFT)), b"\x1b[1;2C");
        assert_eq!(key_bytes(KeyEvent::new(KeyCode::Up, KeyModifiers::ALT)), b"\x1b[1;3A");
        assert_eq!(key_bytes(KeyEvent::new(KeyCode::Delete, KeyModifiers::CONTROL)), b"\x1b[3;5~");
    }
    #[test]
    fn detach_accepts_platform_control_bracket_events_without_catching_plain_keys() {
        assert!(detach_key(KeyEvent::new(
            KeyCode::Char(']'),
            KeyModifiers::CONTROL
        )));
        assert_eq!(
            detach_key(KeyEvent::new(KeyCode::Char('5'), KeyModifiers::CONTROL)),
            cfg!(unix)
        );
        for code in [KeyCode::Char(']'), KeyCode::Char('5'), KeyCode::Char('c')] {
            assert!(!detach_key(KeyEvent::new(code, KeyModifiers::NONE)));
        }
        assert!(!detach_key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        )));
    }
}

#[cfg(test)]
mod subscription_tests {
    use super::*;
    #[test]
    fn subscription_windows_keep_their_mode_and_target_without_recursive_spawning() {
        for tool in ["codex", "claude", "gemini", "opencode", "kilo"] {
            for new_signin in [false, true] {
                let child = subscription_arguments("env with spaces", tool, new_signin, "--window").unwrap();
                let parsed = options(&child).unwrap();
                assert_eq!(parsed.target, "env with spaces");
                assert_eq!(parsed.subscription, Some(tool));
                assert_eq!(parsed.new_signin, new_signin);
                assert!(!parsed.new_window, "the child must attach, never spawn another child");
                let command = subscription_reopen_command("env with spaces", tool, new_signin).unwrap();
                let command = shell_words::split(&command).unwrap();
                let reopened = options(&command[1..]).unwrap();
                assert!(reopened.new_window, "the retry must not take over the caller's terminal");
                assert_eq!(reopened.target, parsed.target);
                assert_eq!(reopened.subscription, parsed.subscription);
                assert_eq!(reopened.new_signin, parsed.new_signin);
                assert!(!command.iter().any(|arg| arg.contains("API_KEY") || arg.contains("auth.json")));
            }
        }
    }

    #[test]
    fn invalid_subscription_flags_fail_before_connecting_or_spawning() {
        for extra in [vec!["--subscription", "sh"], vec!["--subscription", "codex;echo nope"],
            vec!["--new-signin"], vec!["--subscription"],
            vec!["--subscription", "codex", "--project"],
            vec!["--subscription", "codex", "--container", "anything"],
            vec!["--subscription", "codex", "--subscription", "claude"],
            vec!["--window", "--new-window"]] {
            let args = [vec!["terminal", "fixture"], extra].concat().into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(options(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn subscription_terminal_drops_bridge_api_billing_keys_in_its_child_only() {
        for (tool, variable) in [("codex", "OPENAI_API_KEY"), ("claude", "ANTHROPIC_API_KEY"), ("gemini", "GEMINI_API_KEY"), ("opencode", "OPENCODE_API_KEY"), ("kilo", "KILO_API_KEY")] {
            let command = subscription_command(tool, &[]).unwrap();
            assert!(command.contains(&format!("unset {variable}")));
            assert!(command.contains(&format!("exec {tool}")));
            assert!(!command.contains("rm "));
        }
        assert!(subscription_command("arbitrary-command", &[]).is_err());
    }
}
