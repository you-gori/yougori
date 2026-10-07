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
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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

/// Open a visible terminal without borrowing the launcher's stdin or stopping sync.
pub fn open(environment: &str, project: bool, container: Option<&str>) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
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
            shell_words::join(std::iter::once(exe.to_string_lossy().into_owned()).chain(args));
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
                .args(&args)
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
            shell_words::join(std::iter::once(exe.to_string_lossy().into_owned()).chain(args))
        ))
    }
}

pub async fn run(args: &[String]) -> Result<(), String> {
    let window = args.iter().any(|s| s == "--window");
    #[cfg(windows)]
    if window {
        use std::{fs::OpenOptions, os::windows::io::IntoRawHandle};
        use windows_sys::Win32::System::Console::{
            SetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };
        // NEW_CONSOLE with null inherited streams: attach explicitly to the new
        // console, never to the launcher's input or output handles.
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
    let result = run_inner(args).await;
    if window {
        if let Err(error) = &result {
            eprintln!(
                "Could not open the environment shell: {error}\nPress Enter to close this window."
            );
            let _ = io::stdin().read_line(&mut String::new());
        }
    }
    result
}

async fn run_inner(args: &[String]) -> Result<(), String> {
    let target = args
        .get(1)
        .filter(|s| !s.starts_with('-'))
        .ok_or("Usage: yougori terminal ENV [--project] [--container NAME]")?;
    let mut project = false;
    let mut container = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--window" => {}
            "--project" => project = true,
            "--container" if container.is_none() => {
                i += 1;
                let name = args.get(i).ok_or("--container requires a container name")?;
                if name.is_empty() || name.starts_with('-') || name.chars().any(char::is_control) {
                    return Err("Invalid container name".into());
                }
                container = Some(name.as_str());
                project = true;
            }
            _ => return Err("Usage: yougori terminal ENV [--project] [--container NAME]".into()),
        }
        i += 1;
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("Open terminal requires an interactive terminal".into());
    }
    crate::client::start(None).await?;
    let id = crate::public::resolve(target).await?;
    println!("Yougori terminal · {}\nType exit or press Ctrl+] to close this shell. Your workload keeps running.\n", target.chars().filter(|c| !c.is_control()).collect::<String>());
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
    let mut bytes = match key.code {
        KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) && c.is_ascii() => {
            vec![(c.to_ascii_lowercase() as u8) & 0x1f]
        }
        KeyCode::Char(c) => c.to_string().into_bytes(),
        KeyCode::Enter => vec![13],
        KeyCode::Backspace => vec![127],
        KeyCode::Tab => vec![9],
        KeyCode::Esc => vec![27],
        KeyCode::Up => b"\x1b[A".to_vec(),
        KeyCode::Down => b"\x1b[B".to_vec(),
        KeyCode::Right => b"\x1b[C".to_vec(),
        KeyCode::Left => b"\x1b[D".to_vec(),
        KeyCode::Home => b"\x1b[H".to_vec(),
        KeyCode::End => b"\x1b[F".to_vec(),
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::PageUp => b"\x1b[5~".to_vec(),
        KeyCode::PageDown => b"\x1b[6~".to_vec(),
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        _ => vec![],
    };
    if key.modifiers.contains(KeyModifiers::ALT) && !bytes.is_empty() {
        bytes.insert(0, 27);
    }
    bytes
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
struct InputBatch { bytes: Vec<u8>, resize: Option<(u16, u16)>, detached: bool }

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
                Event::Paste(text) => batch.bytes.extend(text.into_bytes()),
                Event::Resize(cols, rows) => batch.resize = Some((cols, rows)),
                _ => {},
            }
            if batch.bytes.len() >= 64 * 1024 { break; }
        }
        Ok(batch)
    }
}

pub async fn attach(id: &str, command: Option<&str>) -> Result<(), String> {
    attach_session(id, command, None).await
}

pub async fn attach_tool(id: &str, tool: &str, arguments: &[String]) -> Result<(), String> {
    if !crate::container_tools::TOOLS.contains(&tool) { return Err("Unknown tool".into()); }
    attach_session(id, None, Some((tool, arguments))).await
}

const TOOL_ENV: &str = "[ ! -r \"$HOME/.local/share/yougori/tool-env.sh\" ] || . \"$HOME/.local/share/yougori/tool-env.sh\"";

fn tool_command(tool: &str, arguments: &[String], installer: Option<&str>, status: &str) -> Result<String, String> {
    let install = if let Some(installer) = installer {
        let parts = shell_words::split(installer).map_err(|_| "Invalid installer launcher")?;
        let path = parts.get(2).ok_or("Invalid installer launcher")?;
        let suffix = path.strip_prefix("/tmp/yougori-install.").and_then(|value| value.strip_suffix("/install.sh")).ok_or("Invalid installer launcher")?;
        if parts.len() != 3 || parts[0] != "exec" || parts[1] != "sh" || suffix.is_empty() || suffix.len() > 32 || !suffix.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err("Invalid installer launcher".into());
        }
        format!("sh {}; ", shell_words::quote(path))
    } else { String::new() };
    let launch = shell_words::join(std::iter::once(tool.to_owned()).chain(arguments.iter().cloned()));
    let cleanup = format!("od_status=$?; rm -f {}; printf '%s\\n' \"$od_status\" > {}; exit \"$od_status\"", shell_words::quote(&format!("{status}.sh")), shell_words::quote(status));
    let script = format!("umask 077; trap {} EXIT; set -e; {install}{TOOL_ENV}; mkdir -p /workspace; cd /workspace; {launch}", shell_words::quote(&cleanup));
    Ok(format!("exec sh -c {}", shell_words::quote(&script)))
}

async fn attach_session(id: &str, command: Option<&str>, tool: Option<(&str, &[String])>) -> Result<(), String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(
            "A shell requires an interactive terminal; the environment is still running".into(),
        );
    }
    let raw = Raw(terminal::is_raw_mode_enabled().map_err(|e| e.to_string())?);
    terminal::enable_raw_mode().map_err(|e| e.to_string())?;
    let session = format!(
        "term-cli-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let (cols, rows) = terminal::size().unwrap_or((100, 30));
    call(
        "terminal_action",
        json!({"environmentId":id,"sessionId":session,"action":"create","cols":cols,"rows":rows}),
    )
    .await?;
    let status = format!("/tmp/yougori-tool-{session}.status");
    let result = async {
        let launch = if let Some((tool, arguments)) = tool {
            let probe = call("execute_environment_command", json!({"request":{"environmentId":id,"command":format!("{TOOL_ENV}; if command -v {tool} >/dev/null 2>&1; then printf ready; else printf missing; fi")}})).await?;
            if probe["exitCode"] != 0 { return Err("Could not check the tool inside this container".into()); }
            let installer = if probe["stdout"].as_str().unwrap_or("").trim() == "ready" { None }
                else { Some(call("prepare_terminal_installer", json!({"environmentId":id,"sessionId":session,"tool":tool})).await?.as_str().ok_or("Invalid installer response")?.to_owned()) };
            let command = tool_command(tool, arguments, installer.as_deref(), &status)?;
            let script = shell_words::split(&command).map_err(|_| "Invalid tool launcher")?.pop().ok_or("Missing tool launcher")?;
            let path = format!("{status}.sh");
            let staged = call("execute_environment_command", json!({"request":{"environmentId":id,"command":format!("umask 077; printf %s {} > {}",shell_words::quote(&script),shell_words::quote(&path))}})).await?;
            if staged["exitCode"] != 0 { return Err("Could not stage the tool launcher inside this container".into()); }
            Some(format!("exec sh {}", shell_words::quote(&path)))
        } else { command.map(str::to_owned) };
        if let Some(command) = launch {
            call("terminal_action", json!({"environmentId":id,"sessionId":session,"action":"write","data":B64.encode(format!("{command}\r"))})).await?;
        }
        let mut offset = 0;
        let mut input_reader = InputReader::default();
        loop {
            let result = call("terminal_action", json!({"environmentId":id,"sessionId":session,"action":"read","offset":offset})).await?;
            let bytes = B64.decode(result["data"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
            io::stdout().write_all(&bytes).map_err(|e| e.to_string())?;
            io::stdout().flush().map_err(|e| e.to_string())?;
            offset = result["offset"].as_u64().unwrap_or(offset);
            if result["done"] == true {
                if tool.is_some() {
                    let exit = call("execute_environment_command", json!({"request":{"environmentId":id,"command":format!("test -f {0} && cat {0} && rm -f {0}",shell_words::quote(&status))}})).await?;
                    let code = exit["stdout"].as_str().unwrap_or("").trim().parse::<u8>().map_err(|_| "The tool session ended without an exit result. The container and files remain.")?;
                    if code != 0 { return Err(format!("The tool session exited with status {code}. Read its terminal output above; the container and files remain.")); }
                }
                break;
            }
            // Send queued input together. Splitting ESC/control reports across
            // RPC round trips makes full-screen tools treat their tails as text.
            let input = input_reader.read_batch()?;
            if input.detached { return Ok(()); }
            if let Some((cols, rows)) = input.resize {
                call("terminal_action", json!({"environmentId":id,"sessionId":session,"action":"resize","cols":cols,"rows":rows})).await?;
            }
            for chunk in input.bytes.chunks(12 * 1024) {
                call("terminal_action", json!({"environmentId":id,"sessionId":session,"action":"write","data":B64.encode(chunk)})).await?;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        Ok(())
    }.await;
    // Close only this new PTY, even on transport/input errors. Never stop the environment.
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
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tool_launcher_preserves_literal_arguments_and_runs_install_before_launch() {
        let args = vec!["--prompt".into(), "spaces; $(touch /tmp/no) and 'quotes'".into()];
        let command = tool_command("codex", &args, Some("exec sh '/tmp/yougori-install.abc123/install.sh'"), "/tmp/status").unwrap();
        let outer = shell_words::split(&command).unwrap();
        assert_eq!(&outer[..3], &["exec", "sh", "-c"]);
        let script = &outer[3];
        assert!(script.find("sh /tmp/yougori-install.abc123/install.sh").unwrap() < script.find("cd /workspace").unwrap());
        let tail = script.split("cd /workspace; ").last().unwrap();
        assert_eq!(shell_words::split(tail).unwrap(), [vec!["codex".to_owned()], args].concat());
        for bad in ["exec sh '/tmp/other/install.sh'", "sh '/tmp/yougori-install.abc/install.sh'", "exec sh '/tmp/yougori-install.a/../install.sh'", "exec sh '/tmp/yougori-install.abc/install.sh' ; whoami"] { assert!(tool_command("codex", &[], Some(bad), "/tmp/status").is_err()); }
        assert!(!tool_command("claude", &[], None, "/tmp/status").unwrap().contains("/install.sh"));
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
