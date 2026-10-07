//! Host shells are intentionally separate from guest terminals. Only the main
//! dashboard and the same-user CLI can access them; output is never broadcast.
mod process;
#[cfg(test)]
mod tests;

use base64::{engine::general_purpose::STANDARD, Engine};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex},
};
use tauri::Manager;
use crate::{AppHandle, WebviewWindow};

const MAX_SESSIONS: usize = 4;
const BUFFER_LIMIT: usize = 256 * 1024;
const CHUNK_LIMIT: usize = 32 * 1024;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostRequest {
    session_id: String,
    action: String,
    data: Option<String>,
    offset: Option<u64>,
    cols: Option<u16>,
    rows: Option<u16>,
    cwd: Option<PathBuf>,
}
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostOutput {
    data: String,
    offset: u64,
    done: bool,
    truncated: bool,
    exit_code: Option<u32>,
}
#[derive(Default)]
struct OutputBuffer {
    bytes: VecDeque<u8>,
    end: u64,
    done: bool,
    exit_code: Option<u32>,
}
impl OutputBuffer {
    fn push(&mut self, bytes: &[u8]) {
        self.end += bytes.len() as u64;
        self.bytes.extend(bytes);
        if self.bytes.len() > BUFFER_LIMIT {
            self.bytes.drain(..self.bytes.len() - BUFFER_LIMIT);
        }
    }
    fn read(&self, offset: u64) -> Result<HostOutput, String> {
        if offset > self.end {
            return Err("Terminal output offset is ahead of this session".into());
        }
        let base = self.end - self.bytes.len() as u64;
        let start = offset.max(base);
        let bytes: Vec<u8> = self
            .bytes
            .iter()
            .skip((start - base) as usize)
            .take(CHUNK_LIMIT)
            .copied()
            .collect();
        let next = start + bytes.len() as u64;
        Ok(HostOutput {
            data: STANDARD.encode(bytes),
            offset: next,
            truncated: offset < base,
            done: self.done && next == self.end,
            exit_code: self.exit_code,
        })
    }
}

struct Session {
    owner: String,
    cwd: PathBuf,
    master: Mutex<Option<Box<dyn MasterPty + Send>>>,
    writer: Arc<Mutex<Option<Box<dyn Write + Send>>>>,
    child: Mutex<Option<Box<dyn Child + Send + Sync>>>,
    process: Mutex<Option<process::ProcessScope>>,
    output: Arc<Mutex<OutputBuffer>>,
}
impl Session {
    fn close_io(&self) {
        self.process.lock().unwrap().take();
        self.writer.lock().unwrap().take();
        self.master.lock().unwrap().take();
    }
    fn close(&self) {
        // Terminate the Windows job before the shell. Interactive tools such as
        // Codex launch through cmd/node and can outlive PowerShell otherwise.
        self.process.lock().unwrap().take();
        if let Some(mut child) = self.child.lock().unwrap().take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            self.close_io();
            let _ = child.wait();
        } else {
            self.close_io();
        }
    }
    fn read(&self, offset: u64) -> Result<HostOutput, String> {
        let mut child = self.child.lock().unwrap();
        if let Some(status) = child
            .as_mut()
            .map(|c| c.try_wait())
            .transpose()
            .map_err(|e| e.to_string())?
            .flatten()
        {
            self.output.lock().unwrap().exit_code = Some(status.exit_code());
            child.take();
            self.close_io();
        }
        drop(child);
        self.output.lock().unwrap().read(offset)
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Default)]
pub struct HostTerminalManager {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    closing: AtomicBool,
    pub(crate) setup: tokio::sync::Mutex<()>,
}
impl HostTerminalManager {
    pub(crate) fn project_directories(&self) -> Vec<PathBuf> {
        self.sessions.lock().unwrap().values().map(|s| s.cwd.clone()).collect()
    }
    pub fn close_owner(&self, owner: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        let ids: Vec<_> = sessions
            .iter()
            .filter(|(_, s)| s.owner == owner)
            .map(|(id, _)| id.clone())
            .collect();
        let closing: Vec<_> = ids
            .into_iter()
            .filter_map(|id| sessions.remove(&id))
            .collect();
        drop(sessions);
        for session in closing {
            session.close();
        }
    }
    pub fn shutdown(&self) {
        self.closing.store(true, Ordering::SeqCst);
        let sessions = std::mem::take(&mut *self.sessions.lock().unwrap());
        for session in sessions.values() {
            session.close();
        }
    }
    fn action(
        &self,
        request: HostRequest,
        owner: &str,
        config: Option<ShellConfig>,
    ) -> Result<HostOutput, String> {
        validate_request(&request)?;
        if request.action == "create" {
            let mut sessions = self.sessions.lock().unwrap();
            if self.closing.load(Ordering::SeqCst) {
                return Err("Yougori is closing; open a new terminal after restarting.".into());
            }
            if sessions.contains_key(&request.session_id) {
                return Err("Host terminal session already exists".into());
            }
            if sessions.len() >= MAX_SESSIONS {
                return Err("Close a host terminal first (maximum four sessions)".into());
            }
            let config = config.ok_or("Missing host shell configuration")?;
            let session = spawn_shell(owner, config, size(&request)?)?;
            sessions.insert(request.session_id, session);
            return Ok(HostOutput::default());
        }
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.get(&request.session_id).cloned() else {
            return if request.action == "close" {
                Ok(HostOutput {
                    done: true,
                    ..Default::default()
                })
            } else {
                Err("Host terminal is closed. Open a new tab.".into())
            };
        };
        if session.owner != owner {
            return Err("This host terminal belongs to a different client".into());
        }
        if request.action == "close" {
            sessions.remove(&request.session_id);
        }
        drop(sessions);
        match request.action.as_str() {
            "read" => session.read(request.offset.unwrap_or(0)),
            "write" => {
                let bytes = STANDARD
                    .decode(request.data.unwrap_or_default())
                    .map_err(|_| "Invalid terminal input encoding")?;
                if bytes.len() > CHUNK_LIMIT {
                    return Err("Terminal input exceeds 32 KB; send it in smaller chunks".into());
                }
                let mut writer = session.writer.lock().unwrap();
                writer
                    .as_mut()
                    .ok_or("Host shell has exited")?
                    .write_all(&bytes)
                    .map_err(|e| format!("Write to host shell: {e}"))?;
                Ok(HostOutput::default())
            }
            "resize" => {
                if let Some(master) = session.master.lock().unwrap().as_ref() {
                    master.resize(size(&request)?).map_err(|e| e.to_string())?;
                }
                Ok(HostOutput::default())
            }
            "close" => {
                session.close();
                Ok(HostOutput {
                    done: true,
                    ..Default::default()
                })
            }
            _ => unreachable!(),
        }
    }
}
fn size(request: &HostRequest) -> Result<PtySize, String> {
    let (cols, rows) = (request.cols.unwrap_or(100), request.rows.unwrap_or(24));
    if !(2..=500).contains(&cols) || !(2..=250).contains(&rows) {
        return Err("Terminal dimensions are outside the supported range".into());
    }
    Ok(PtySize {
        cols,
        rows,
        pixel_width: 0,
        pixel_height: 0,
    })
}
pub(crate) fn validate_request(request: &HostRequest) -> Result<(), String> {
    if !request.session_id.starts_with("host-")
        || request.session_id.len() > 80
        || !request
            .session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("Invalid host terminal session ID".into());
    }
    if !["create", "read", "write", "resize", "close"].contains(&request.action.as_str()) {
        return Err("Unsupported host terminal action".into());
    }
    if request.data.as_ref().is_some_and(|s| s.len() > 48 * 1024) {
        return Err("Terminal input is too large".into());
    }
    if request.action == "create" || request.action == "resize" {
        size(request)?;
    }
    if request.action != "create" && request.cwd.is_some() {
        return Err("A working folder can only be chosen for a new terminal".into());
    }
    Ok(())
}

pub(crate) fn require_dashboard(label: &str) -> Result<(), String> {
    if label != "main" {
        return Err("Host computer access is only available from the Yougori dashboard".into());
    }
    Ok(())
}
fn home_directory() -> Result<PathBuf, String> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .ok_or("Cannot locate your home folder")?;
    if !home.is_absolute() || !home.is_dir() {
        return Err("Your home folder is unavailable".into());
    }
    Ok(home)
}
pub(crate) fn default_workspace() -> Result<PathBuf, String> { workspace_directory(&home_directory()?) }
fn workspace_directory(profile: &Path) -> Result<PathBuf, String> {
    if !profile.is_absolute() || !profile.is_dir() {
        return Err("Your home folder is unavailable; cannot locate the Yougori workspace".into());
    }
    // Kept away from both personal documents and Yougori's runtime/state files.
    // This is a starting directory, NOT an OS access restriction.
    // Previous workspaces stay in place; new sessions use the current product name.
    Ok(profile.join("Yougori").join("Workspace"))
}
fn prepare_working_directory(profile: &Path, requested: Option<&Path>) -> Result<PathBuf, String> {
    let workspace = workspace_directory(profile)?;
    let directory = requested.unwrap_or(&workspace);
    if directory == workspace {
        for part in [workspace.parent().ok_or("Missing workspace parent")?.to_path_buf(), workspace.clone()] {
            match std::fs::create_dir(&part) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(format!(
                    "Cannot create Yougori workspace {}: {error}. Choose another working folder.",
                    part.display()
                )),
            }
            let metadata = std::fs::symlink_metadata(&part).map_err(|e| e.to_string())?;
            let redirected = metadata.file_type().is_symlink();
            #[cfg(windows)]
            let redirected = {
                use std::os::windows::fs::MetadataExt;
                // FILE_ATTRIBUTE_REPARSE_POINT includes junctions as well as symlinks.
                redirected || metadata.file_attributes() & 0x400 != 0
            };
            if !metadata.is_dir() || redirected {
                return Err(format!("The Yougori workspace path {} must be a normal folder, not a file or redirected folder. Nothing there was replaced.", part.display()));
            }
        }
    } else if !directory.is_absolute() || !directory.is_dir() {
        // A failed custom selection must never fall back to the user's home.
        return Err("Choose an existing absolute working folder".into());
    }
    Ok(directory.to_path_buf())
}
pub(crate) fn cli_executable(app: &AppHandle) -> Result<PathBuf, String> {
    let name = if cfg!(windows) {
        "yougori.exe"
    } else {
        "yougori"
    };
    let mut candidates = Vec::new();
    #[cfg(debug_assertions)]
    candidates.push(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("resources/cli")
            .join(name),
    );
    candidates.push(crate::resource_dir(app)?.join("cli").join(name));
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("cli").join(name));
        }
    }
    candidates.into_iter().find(|p|p.is_file()).and_then(|p|p.canonicalize().ok()).ok_or_else(||"The Yougori CLI is missing. Reinstall Yougori; in a source checkout run npm run cli:bundle.".into())
}
fn search_command(name: &str) -> Option<PathBuf> {
    for dir in host_command_paths().into_iter()
        .filter(|p| p.is_absolute())
    {
        for suffix in if cfg!(windows) {
            vec![".exe", ".cmd", ".bat"]
        } else {
            vec![""]
        } {
            let path = dir.join(format!("{name}{suffix}"));
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}
fn host_command_paths() -> Vec<PathBuf> {
    let mut paths: Vec<_> = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
    for path in crate::neocloud::install::managed_cli_dirs() {
        if !paths.contains(&path) { paths.insert(0, path); }
    }
    // Finder does not inherit shell profiles. Do not execute a login shell to
    // discover PATH, nor source arbitrary startup scripts in the CLI panel.
    if cfg!(target_os = "macos") {
        for path in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
            let path = PathBuf::from(path);
            if !paths.contains(&path) { paths.push(path); }
        }
    }
    paths
}
struct ShellConfig {
    shell: PathBuf,
    cli: PathBuf,
    app: PathBuf,
    cwd: PathBuf,
    load_profile: bool,
}
fn configure_terminal_environment(command: &mut CommandBuilder) {
    // A desktop launched by a build tool can inherit its non-terminal settings.
    // These overrides apply only to the new interactive shell, not the app or OS.
    command.env_remove("NO_COLOR");
    if command.get_env("FORCE_COLOR") == Some(std::ffi::OsStr::new("0")) {
        command.env_remove("FORCE_COLOR");
    }
    command.env("TERM", "xterm-256color");
    command.env("COLORTERM", "truecolor");
    command.env("CLICOLOR", "1");
    command.env("TERM_PROGRAM", "Yougori");
}
fn shell_path() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        if let Some(pwsh) = search_command("pwsh") {
            return Ok(pwsh);
        }
        let shell = PathBuf::from(
            std::env::var_os("SystemRoot").ok_or("Windows system directory is unavailable")?,
        )
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        if shell.is_file() {
            Ok(shell)
        } else {
            Err("PowerShell is not installed".into())
        }
    }
    #[cfg(unix)]
    {
        Ok(std::env::var_os("SHELL")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute() && p.is_file())
            .unwrap_or_else(|| PathBuf::from(if cfg!(target_os = "macos") { "/bin/zsh" } else { "/bin/sh" })))
    }
}
fn spawn_shell(owner: &str, config: ShellConfig, size: PtySize) -> Result<Arc<Session>, String> {
    if process::is_elevated()? {
        return Err("Yougori is running as administrator. Reopen it normally to use the host terminal safely.".into());
    }
    if !config.cwd.is_absolute() || !config.cwd.is_dir() {
        return Err("Choose an existing absolute working folder".into());
    }
    let mut command = CommandBuilder::new(&config.shell);
    let mut paths = vec![config
        .cli
        .parent()
        .ok_or("Missing CLI folder")?
        .to_path_buf()];
    paths.extend(host_command_paths());
    command.env(
        "PATH",
        std::env::join_paths(paths).map_err(|e| e.to_string())?,
    );
    command.env("OPENDOCK_CLI", &config.cli);
    command.env("OPENDOCK_APP", &config.app);
    command.env("YOUGORI_CLI", &config.cli);
    command.env("YOUGORI_APP", &config.app);
    configure_terminal_environment(&mut command);
    command.cwd(&config.cwd);
    #[cfg(windows)]
    {
        // Fixed bootstrap only, no interpolated paths or user-supplied code.
        // No execution-policy change and no elevation. .cmd aliases avoid npm's
        // optional .ps1 wrappers under a restricted PowerShell script policy.
        let mut bootstrap =
            String::from("function global:yougori { & $env:YOUGORI_CLI @args }; function global:opendock { & $env:YOUGORI_CLI @args }; ");
        for name in ["codex", "claude", "gemini", "kilo", "opencode"] {
            if let Some(path) = search_command(name) {
                command.env(format!("YOUGORI_AGENT_{}", name.to_uppercase()), path);
                bootstrap.push_str(&format!(
                    "function global:{name} {{ & $env:YOUGORI_AGENT_{} @args }}; ",
                    name.to_uppercase()
                ));
            }
        }
        bootstrap.push_str(
            "Import-Module PSReadLine -ErrorAction SilentlyContinue; if (Get-Module PSReadLine) { Set-PSReadLineOption -HistorySaveStyle SaveNothing }; ",
        );
        command.arg("-NoLogo");
        if !config.load_profile { command.arg("-NoProfile"); }
        command.args(["-NoExit", "-Command", &bootstrap]);
    }
    #[cfg(unix)]
    {
        match config.shell.file_name().and_then(|s| s.to_str()) {
            Some("bash" | "zsh") if config.load_profile => command.args(["-l", "-i"]),
            Some("bash") => command.args(["--noprofile", "--norc", "-i"]),
            Some("zsh") => command.args(["-f", "-i"]),
            _ => command.arg("-i"),
        }
    }
    let pair = native_pty_system()
        .openpty(size)
        .map_err(|e| format!("Cannot open the host terminal: {e}"))?;
    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer = Arc::new(Mutex::new(Some(
        pair.master.take_writer().map_err(|e| e.to_string())?,
    )));
    let input = writer.clone();
    let output = Arc::new(Mutex::new(OutputBuffer::default()));
    let sink = output.clone();
    let (initialized_tx, initialized_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    // ConPTY must be drained while closing, including failed startup paths.
    std::thread::Builder::new()
        .name("yougori-host-output".into())
        .spawn(move || {
            let mut bytes = [0u8; 8192];
            let mut startup = cfg!(windows);
            let mut initial = Vec::new();
            if !startup {
                let _ = initialized_tx.send(Ok(()));
            }
            loop {
                match reader.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(n) => {
                        if startup {
                            initial.extend_from_slice(&bytes[..n]);
                            // portable-pty's ConPTY inherits the cursor. A new
                            // Yougori terminal always starts at 1,1. Resolve
                            // this first handshake before accepting user input;
                            // ConPTY otherwise discards early agent commands.
                            let query = b"\x1b[6n";
                            if initial.len() < query.len() && query.starts_with(&initial) {
                                continue;
                            }
                            if initial.starts_with(query) {
                                let result = input
                                    .lock()
                                    .unwrap()
                                    .as_mut()
                                    .ok_or_else(|| {
                                        "Host terminal closed during startup".to_string()
                                    })
                                    .and_then(|writer| {
                                        writer.write_all(b"\x1b[1;1R").map_err(|e| e.to_string())
                                    });
                                if let Err(error) = result {
                                    let _ = initialized_tx.send(Err(error));
                                    break;
                                }
                                sink.lock().unwrap().push(&initial[query.len()..]);
                            } else {
                                sink.lock().unwrap().push(&initial);
                            }
                            startup = false;
                            let _ = initialized_tx.send(Ok(()));
                        } else {
                            sink.lock().unwrap().push(&bytes[..n]);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            if startup {
                let _ =
                    initialized_tx.send(Err("Host terminal closed before initialization".into()));
            }
            sink.lock().unwrap().done = true;
        })
        .map_err(|e| e.to_string())?;
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|e| format!("Start host shell: {e}"))?;
    let scope = match process::ProcessScope::attach(child.as_ref()) {
        Ok(scope) => scope,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    drop(pair.slave);
    let session = Arc::new(Session {
        owner: owner.into(),
        cwd: config.cwd,
        master: Mutex::new(Some(pair.master)),
        writer,
        child: Mutex::new(Some(child)),
        process: Mutex::new(Some(scope)),
        output,
    });
    initialized_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .map_err(|_| {
            "Host terminal did not initialize. Close this tab and try again.".to_string()
        })??;
    Ok(session)
}

pub(crate) fn info(app: &AppHandle, owner: &str) -> Result<serde_json::Value, String> {
    let cli = cli_executable(app)?;
    let directory = yougori_cli::skills::default_directory()?;
    let skill = yougori_cli::skills::status_at(&directory, &cli).unwrap_or_else(|e| {
        yougori_cli::skills::SkillStatus {
            state: "conflict",
            path: directory,
            message: e,
        }
    });
    let sessions: Vec<_> = app
        .state::<HostTerminalManager>()
        .sessions
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, session)| session.owner == owner)
        .map(|(id, session)| serde_json::json!({"sessionId":id,"cwd":session.cwd}))
        .collect();
    Ok(
        serde_json::json!({"shell":if cfg!(windows){"PowerShell"}else{"Shell"},"cwd":workspace_directory(&home_directory()?)?,"sourceCheckout":development_source_checkout(),"cliPath":cli,"cliVersion":env!("CARGO_PKG_VERSION"),"protocolVersion":yougori_cli::wire::VERSION,"elevated":process::is_elevated()?,"maxSessions":MAX_SESSIONS,"sessions":sessions,"skill":skill,"canonicalSkill":yougori_cli::skills::descriptor(&cli)?,"managedCopies":yougori_cli::skills::discovery_copies(&cli)?,"agentInstructions":format!("Read the canonical Yougori skill at {}. Version {} (protocol {}). Fetch only the task's reference with `yougori skills print --topic TOPIC`; `--all` explicitly fetches the complete guide. Carry existing task authorization forward.",yougori_cli::skills::default_directory()?.join("SKILL.md").display(),env!("CARGO_PKG_VERSION"),yougori_cli::wire::VERSION),"agents":[{"id":"codex","name":"Codex","available":search_command("codex").is_some()},{"id":"claude","name":"Claude","available":search_command("claude").is_some()},{"id":"gemini","name":"Gemini","available":search_command("gemini").is_some()}]}),
    )
}
fn validate_source_checkout(path: &Path) -> Result<PathBuf, String> {
    let root = path.canonicalize().map_err(|_| "Choose an existing Yougori source folder".to_string())?;
    if !root.join("package.json").is_file()
        || !root.join("src-tauri/Cargo.toml").is_file()
        || !root.join("src/components/host-cli-view.tsx").is_file()
    {
        return Err("This folder is not a Yougori source checkout. Choose the folder containing package.json and src-tauri.".into());
    }
    let package: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join("package.json")).map_err(|e| e.to_string())?)
        .map_err(|_| "The selected source checkout has an invalid package.json".to_string())?;
    if package.get("name").and_then(|name| name.as_str()) != Some("yougori") {
        return Err("The selected folder is not a Yougori source checkout".into());
    }
    Ok(root)
}
fn development_source_checkout() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    { return Path::new(env!("CARGO_MANIFEST_DIR")).parent().and_then(|path| validate_source_checkout(path).ok()); }
    #[cfg(not(debug_assertions))]
    { None }
}
#[tauri::command]
pub fn validate_edit_app_folder(window: WebviewWindow, path: PathBuf) -> Result<PathBuf, String> {
    require_dashboard(window.label())?;
    validate_source_checkout(&path)
}
pub(crate) async fn setup_access(
    app: &AppHandle,
) -> Result<yougori_cli::skills::SkillStatus, String> {
    let manager = app.state::<HostTerminalManager>();
    let _guard = manager.setup.lock().await;
    let cli = cli_executable(app)?;
    tokio::task::spawn_blocking(move || yougori_cli::skills::install_default(&cli))
        .await
        .map_err(|e| e.to_string())?
}
pub(crate) async fn action_for_owner(
    app: &AppHandle,
    request: HostRequest,
    owner: String,
) -> Result<HostOutput, String> {
    validate_request(&request)?;
    let config = if request.action == "create" {
        if process::is_elevated()? {
            return Err("Yougori is running as administrator. Reopen it normally to use the host terminal safely.".into());
        }
        Some(ShellConfig {
            shell: shell_path()?,
            cli: cli_executable(app)?,
            app: std::env::current_exe().map_err(|e| e.to_string())?,
            cwd: prepare_working_directory(&home_directory()?, request.cwd.as_deref())?,
            load_profile: true,
        })
    } else {
        None
    };
    let app = app.clone();
    tokio::task::spawn_blocking(move || {
        app.state::<HostTerminalManager>()
            .action(request, &owner, config)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub fn get_host_terminal_info(
    window: WebviewWindow,
    app: AppHandle,
) -> Result<serde_json::Value, String> {
    require_dashboard(window.label())?;
    info(&app, window.label())
}
#[tauri::command]
pub async fn set_up_agent_access(
    window: WebviewWindow,
    app: AppHandle,
) -> Result<yougori_cli::skills::SkillStatus, String> {
    require_dashboard(window.label())?;
    setup_access(&app).await
}
#[tauri::command]
pub async fn host_terminal_action(
    window: WebviewWindow,
    app: AppHandle,
    request: HostRequest,
) -> Result<HostOutput, String> {
    require_dashboard(window.label())?;
    action_for_owner(&app, request, window.label().into()).await
}
