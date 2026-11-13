//! bash: runs a command in the project folder. Output streams to the screen as it comes; the
//! whole process group is killed on cancel or timeout (and whenever the run is dropped).
use super::{number_arg, real, required, slash, text_arg, Output, Tool, ToolCtx};
use crate::native::cancel::Cancel;
use crate::native::permissions::{bash_subjects_placed, cmd_subjects, Subject};
use crate::native::shell::Simple;
use crate::native::util;
use crate::protocol::{ToolContent, ToolKind, ToolStatus, ToolUpdate};
use async_trait::async_trait;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

const DEFAULT_TIMEOUT: u64 = 120;
const MAX_TIMEOUT: u64 = 600;
/// Output kept in memory: this much from the start, then a rolling tail.
const HEAD_BYTES: usize = 8 * 1024 * 1024;
const TAIL_BYTES: usize = 1024 * 1024;
/// What the screen gets while a command runs.
const SCREEN_BYTES: usize = 16 * 1024;
const SCREEN_EVERY: Duration = Duration::from_millis(150);
/// The names models give the folder a command runs in.
pub const WORKDIR: &[&str] = &["workdir", "cwd", "directory", "dir"];

/// The folder the call names to run in, made absolute; None when it names none.
pub fn folder(args: &Value, ctx: &ToolCtx<'_>) -> Option<PathBuf> {
    text_arg(args, WORKDIR).filter(|dir| !dir.trim().is_empty()).map(|dir| ctx.resolve(&dir))
}

/// Where the simple commands of a line run, followed through `cd` and `pushd` to a folder
/// written out; once a line changes folder in a way this cannot follow, nowhere known.
struct Walk {
    start: Option<PathBuf>,
    here: Option<PathBuf>,
    home: Option<PathBuf>,
    /// The project folder, as the permission rules name it.
    project: String,
    /// CDPATH is set: `cd name` may go elsewhere.
    cdpath: bool,
    /// `set` ran: `cd` may resolve links (`set -P`).
    physical: bool,
}

impl Walk {
    fn new(start: &Path, ctx: &ToolCtx<'_>) -> Walk {
        let shared = ctx.shared();
        let start = Some(real(start));
        Walk {
            here: start.clone(),
            start,
            home: shared.home.clone(),
            project: shared.vars.cwd.clone(),
            cdpath: shared.env.get("CDPATH").is_some_and(|p| !p.trim().is_empty()),
            physical: false,
        }
    }

    /// The folder to name for a command run in `folder`: None inside the project.
    fn label(&self, folder: &Option<PathBuf>) -> Option<String> {
        let Some(folder) = folder else { return Some("a folder that cannot be told before it runs".into()) };
        let text = slash(folder);
        let base = self.project.trim_end_matches('/');
        let inside = text == self.project || text == base || text.starts_with(&format!("{base}/"));
        (!inside).then_some(text)
    }

    /// Where `simple` runs (None: no command, the line's start), and where the next one will.
    fn place(&mut self, simple: Option<&Simple>) -> Option<String> {
        let Some(simple) = simple else { return self.label(&self.start.clone()) };
        let at = self.label(&self.here.clone());
        let words = simple.command_words();
        let program = words.first().map(String::as_str).unwrap_or("");
        if program == "set" {
            self.physical = true;
        }
        if matches!(program, "cd" | "pushd") {
            self.here = self.moved(&words[1..]);
        } else if words.iter().any(|w| matches!(w.as_str(), "cd" | "pushd" | "popd")) {
            // `builtin cd`, `eval cd`, `popd`: somewhere this does not follow.
            self.here = None;
        }
        at
    }

    fn moved(&self, args: &[String]) -> Option<PathBuf> {
        let here = self.here.as_ref()?;
        let mut target = None;
        for arg in args {
            match arg.as_str() {
                "-L" | "--" => {}
                "-P" | "-e" | "-@" => return None,
                other if target.is_none() => target = Some(other),
                _ => return None,
            }
        }
        let target = match target {
            None => return self.home.as_ref().map(|home| real(home)),
            Some(target) => target,
        };
        // CDPATH is searched for a name that does not start with /, ~, . or ..
        let searched = !["/", "~", "./", "../"].iter().any(|start| target.starts_with(start)) && !matches!(target, "." | "..");
        if self.physical
            || target == "-"
            || target.starts_with('+')
            || target.contains(['$', '`', '*', '?', '[', '{', '\\'])
            || (self.cdpath && searched)
        {
            return None;
        }
        // `cd` resolves `..` as written (-L), then the folder is where it really is.
        Some(real(&super::absolute(here, target, self.home.as_deref())))
    }
}

/// The walk of a call's line, from the folder it names or the project folder.
fn walk(args: &Value, ctx: &ToolCtx<'_>) -> Walk {
    let start = folder(args, ctx).unwrap_or_else(|| ctx.cwd().to_path_buf());
    Walk::new(&start, ctx)
}

/// A line's subjects as bash reads it, each named with its folder when it runs elsewhere.
pub fn posix_subjects(command: &str, args: &Value, ctx: &ToolCtx<'_>) -> Vec<Subject> {
    let mut walk = walk(args, ctx);
    bash_subjects_placed(command, |simple| walk.place(simple))
}

pub struct Bash;

#[async_trait]
impl Tool for Bash {
    fn name(&self) -> &str {
        "bash"
    }

    fn description(&self) -> String {
        "Run a shell command in the project folder and get its output and exit code. Use it to build, test, run \
         programs, use git and install packages. Do not use it to read, search or edit files: read, grep, glob and \
         edit do that better. Commands get no input, so pass flags such as --yes. Timeout 120 seconds unless you set \
         another (at most 600)."
            .into()
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "description": "The command line to run." },
                "timeout": { "type": "integer", "description": "Seconds before it is stopped (default 120, at most 600)." },
                "workdir": { "type": "string", "description": "Folder to run it in, if not the project folder." }
            },
            "required": ["command"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Execute
    }

    fn title(&self, args: &Value, _ctx: &ToolCtx<'_>) -> String {
        util::one_line(&text_arg(args, &["command", "cmd"]).unwrap_or_default(), 80)
    }

    fn subjects(&self, args: &Value, ctx: &ToolCtx<'_>) -> Result<Vec<Subject>, String> {
        let command = required(args, &["command", "cmd"])?;
        if cfg!(windows) {
            // cmd.exe runs it, whose quoting and operators the shell reading does not know.
            return Ok(cmd_subjects(&command, walk(args, ctx).place(None)));
        }
        Ok(posix_subjects(&command, args, ctx))
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let command = required(&args, &["command", "cmd"])?;
        let seconds = match number_arg(&args, &["timeout", "timeout_seconds"]) {
            // Agents trained on other tools often give milliseconds.
            Some(n) if n >= 1000.0 => (n / 1000.0).ceil() as u64,
            Some(n) if n >= 1.0 => n.ceil() as u64,
            _ => DEFAULT_TIMEOUT,
        }
        .min(MAX_TIMEOUT);
        let workdir = match folder(&args, ctx) {
            Some(path) => {
                if !path.is_dir() {
                    return Err(format!("The folder {} does not exist.", ctx.show(&path)));
                }
                path
            }
            None => ctx.cwd().to_path_buf(),
        };
        let mut screen = String::new();
        let mut last_sent = Instant::now() - SCREEN_EVERY;
        let call = ctx.call.to_owned();
        let shown_command = command.clone();
        let ran = run(&command, &workdir, &ctx.shared().env, Duration::from_secs(seconds), ctx.cancel(), &mut |bytes| {
            screen.push_str(&String::from_utf8_lossy(bytes));
            if screen.len() > SCREEN_BYTES * 2 {
                let keep = util::cut_tail(&screen, SCREEN_BYTES).to_owned();
                screen = keep;
            }
            if last_sent.elapsed() >= SCREEN_EVERY {
                last_sent = Instant::now();
                ctx.update(ToolUpdate {
                    id: call.clone(),
                    status: Some(ToolStatus::InProgress),
                    content: Some(vec![ToolContent::Terminal {
                        command: Some(shown_command.clone()),
                        output: clean(util::cut_tail(&screen, SCREEN_BYTES)),
                        exit_code: None,
                    }]),
                    ..Default::default()
                });
            }
        })
        .await?;
        let output = clean(&String::from_utf8_lossy(&ran.output));
        let mut text = if output.trim().is_empty() { "(no output)".to_owned() } else { output.trim_end().to_owned() };
        if ran.dropped > 0 {
            text.push_str(&format!(
                "\n[{} MB in the middle of the output were not kept.]",
                ran.dropped / (1024 * 1024) + 1
            ));
        }
        let failed = match ran.end {
            End::Exited => {
                match (ran.exit, ran.signal) {
                    (Some(code), _) => text.push_str(&format!("\n\nExit code: {code}")),
                    (None, Some(signal)) => text.push_str(&format!("\n\nKilled by signal {signal}")),
                    (None, None) => {}
                }
                false
            }
            End::TimedOut => {
                text.push_str(&format!(
                    "\n\nStopped after {seconds} s: the command did not finish in time. Give a longer timeout, or start \
                     servers and watchers in the background (command > log 2>&1 &)."
                ));
                true
            }
            End::Cancelled => {
                text.push_str("\n\nStopped by the person.");
                true
            }
        };
        Ok(Output {
            text,
            content: vec![ToolContent::Terminal {
                command: Some(command),
                output: util::cut_tail(&output, SCREEN_BYTES).to_owned(),
                exit_code: ran.exit,
            }],
            failed,
            ..Output::default()
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Exited,
    TimedOut,
    Cancelled,
}

#[derive(Debug)]
pub struct Ran {
    /// The output, stdout and stderr interleaved as they came.
    pub output: Vec<u8>,
    /// Bytes from the middle that were not kept.
    pub dropped: u64,
    pub exit: Option<i32>,
    pub signal: Option<i32>,
    pub end: End,
}

/// Kills the process group when dropped, unless the command ended by itself.
struct Group {
    pid: Option<u32>,
}

impl Group {
    fn kill(&mut self) {
        if let Some(pid) = self.pid.take() {
            kill_tree(pid);
        }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Kills a process and everything it started (its process group on Unix, its tree on Windows).
pub fn kill_tree(pid: u32) {
    #[cfg(unix)]
    {
        // The shell leads its own group (process_group(0)), so this reaches its children too.
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/T", "/F", "/PID", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn shell(command: &str) -> tokio::process::Command {
    #[cfg(unix)]
    {
        let shell = ["/bin/bash", "/usr/bin/bash"].into_iter().find(|p| Path::new(p).exists()).unwrap_or("/bin/sh");
        let mut cmd = tokio::process::Command::new(shell);
        cmd.arg("-c").arg(command);
        cmd.process_group(0);
        cmd
    }
    #[cfg(windows)]
    {
        let mut cmd = tokio::process::Command::new("cmd");
        cmd.raw_arg("/D").raw_arg("/S").raw_arg("/C").raw_arg(format!("\"{command}\""));
        cmd.creation_flags(0x0800_0000); // no console window
        cmd
    }
}

/// Runs `command` with exactly `env`, no input, until it ends, the timeout or a cancel.
pub async fn run(
    command: &str,
    cwd: &Path,
    env: &BTreeMap<String, String>,
    timeout: Duration,
    cancel: &Cancel,
    on_output: &mut (dyn FnMut(&[u8]) + Send),
) -> Result<Ran, String> {
    let mut cmd = shell(command);
    cmd.current_dir(cwd)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| format!("The shell could not start: {e}."))?;
    let mut group = Group { pid: child.id() };
    let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(64);
    let mut pumps = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        pumps.push(tokio::spawn(pump(stdout, sender.clone())));
    }
    if let Some(stderr) = child.stderr.take() {
        pumps.push(tokio::spawn(pump(stderr, sender.clone())));
    }
    drop(sender);
    let deadline = tokio::time::Instant::now() + timeout;
    let far = tokio::time::Instant::now() + Duration::from_secs(365 * 24 * 3600);
    let mut capture = Capture::default();
    let mut status = None;
    let mut exited_at: Option<tokio::time::Instant> = None;
    let mut pipes_open = true;
    let end = loop {
        if status.is_some() && !pipes_open {
            break End::Exited;
        }
        // A background child may keep the pipes open after the shell exits: stop reading soon.
        let grace = exited_at.map(|at| at + Duration::from_millis(300)).unwrap_or(far);
        tokio::select! {
            chunk = receiver.recv(), if pipes_open => match chunk {
                Some(bytes) => {
                    on_output(&bytes);
                    capture.push(&bytes);
                }
                None => pipes_open = false,
            },
            waited = child.wait(), if status.is_none() => {
                status = Some(waited.map_err(|e| format!("The command could not be watched: {e}."))?);
                exited_at = Some(tokio::time::Instant::now());
            }
            _ = tokio::time::sleep_until(grace), if exited_at.is_some() => break End::Exited,
            _ = tokio::time::sleep_until(deadline) => break End::TimedOut,
            _ = cancel.cancelled() => break End::Cancelled,
        }
    };
    if end == End::Exited {
        // Ended by itself: anything it left running in the background stays.
        group.pid = None;
    } else {
        group.kill();
        if let Ok(Ok(waited)) = tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
            status = Some(waited);
        }
        // What the pipes still hold.
        let drain = tokio::time::sleep(Duration::from_millis(100));
        tokio::pin!(drain);
        loop {
            tokio::select! {
                chunk = receiver.recv() => match chunk {
                    Some(bytes) => capture.push(&bytes),
                    None => break,
                },
                _ = &mut drain => break,
            }
        }
    }
    for pump in pumps {
        pump.abort();
    }
    let (output, dropped) = capture.finish();
    let (exit, signal) = match status {
        Some(status) => (status.code(), signal_of(&status)),
        None => (None, None),
    };
    Ok(Ran { output, dropped, exit: if end == End::Exited { exit } else { None }, signal, end })
}

#[cfg(unix)]
fn signal_of(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn signal_of(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

async fn pump(mut reader: impl tokio::io::AsyncRead + Unpin, sender: mpsc::Sender<Vec<u8>>) {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                if sender.send(buffer[..read].to_vec()).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[derive(Default)]
struct Capture {
    head: Vec<u8>,
    tail: Vec<u8>,
    total: u64,
}

impl Capture {
    fn push(&mut self, bytes: &[u8]) {
        self.total += bytes.len() as u64;
        let room = HEAD_BYTES.saturating_sub(self.head.len());
        let (into_head, rest) = bytes.split_at(room.min(bytes.len()));
        self.head.extend_from_slice(into_head);
        if !rest.is_empty() {
            self.tail.extend_from_slice(rest);
            if self.tail.len() > TAIL_BYTES * 2 {
                let cut = self.tail.len() - TAIL_BYTES;
                self.tail.drain(..cut);
            }
        }
    }

    fn finish(mut self) -> (Vec<u8>, u64) {
        if self.tail.len() > TAIL_BYTES {
            let cut = self.tail.len() - TAIL_BYTES;
            self.tail.drain(..cut);
        }
        let kept = (self.head.len() + self.tail.len()) as u64;
        let dropped = self.total - kept;
        if dropped > 0 {
            self.head.extend_from_slice(b"\n[...]\n");
        }
        self.head.extend_from_slice(&self.tail);
        (self.head, dropped)
    }
}

/// Terminal output as text: colour codes removed, progress lines redrawn with `\r` reduced to
/// what they show last.
pub fn clean(text: &str) -> String {
    static ANSI: OnceLock<Regex> = OnceLock::new();
    let ansi = ANSI.get_or_init(|| {
        Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]").unwrap()
    });
    let plain = ansi.replace_all(text, "");
    plain
        .split('\n')
        .map(|line| {
            let line = line.strip_suffix('\r').unwrap_or(line);
            match line.rfind('\r') {
                Some(at) => &line[at + 1..],
                None => line,
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> BTreeMap<String, String> {
        std::env::vars().collect()
    }

    #[test]
    fn terminal_codes_and_progress_redraws_are_cleaned() {
        assert_eq!(clean("\x1b[31merror\x1b[0m: x\n10%\r50%\r100%\ndone\r\n"), "error: x\n100%\ndone\n");
    }

    #[tokio::test]
    async fn output_and_exit_code_come_back() {
        let folder = tempfile::tempdir().unwrap();
        let command = if cfg!(windows) { "echo one && echo two 1>&2 && exit 3" } else { "echo one; echo two >&2; exit 3" };
        let mut streamed = Vec::new();
        let ran = run(command, folder.path(), &env(), Duration::from_secs(30), &Cancel::new(), &mut |b| {
            streamed.extend_from_slice(b)
        })
        .await
        .unwrap();
        let text = String::from_utf8_lossy(&ran.output);
        assert!(text.contains("one") && text.contains("two"), "{text}");
        assert_eq!((ran.end, ran.exit), (End::Exited, Some(3)));
        assert_eq!(streamed, ran.output);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_timeout_kills_the_whole_group() {
        let folder = tempfile::tempdir().unwrap();
        let marker = folder.path().join("survived");
        let command = format!("(sleep 2; touch {}) & sleep 30", marker.display());
        let started = Instant::now();
        let ran = run(&command, folder.path(), &env(), Duration::from_millis(300), &Cancel::new(), &mut |_| {}).await.unwrap();
        assert_eq!(ran.end, End::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert!(!marker.exists(), "the background child was killed with the group");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancel_stops_a_running_command() {
        let folder = tempfile::tempdir().unwrap();
        let cancel = Cancel::new();
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            trigger.cancel();
        });
        let started = Instant::now();
        let ran = run("echo started; sleep 30", folder.path(), &env(), Duration::from_secs(60), &cancel, &mut |_| {})
            .await
            .unwrap();
        assert_eq!(ran.end, End::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(String::from_utf8_lossy(&ran.output).contains("started"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_background_child_does_not_hold_the_call_open() {
        let folder = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let ran = run("sleep 20 & echo launched", folder.path(), &env(), Duration::from_secs(60), &Cancel::new(), &mut |_| {})
            .await
            .unwrap();
        assert_eq!(ran.end, End::Exited);
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn cmd_never_runs_a_program_lying_in_the_working_folder_instead_of_the_real_one() {
        let folder = tempfile::tempdir().unwrap();
        let marker = folder.path().join("ran-the-copy-in-the-folder");
        std::fs::write(folder.path().join("hostname.bat"), format!("@echo off\r\necho x > \"{}\"\r\n", marker.display())).unwrap();
        let mut spec = crate::native::testutil::spec("http://127.0.0.1:9", folder.path(), &folder.path().join("state"));
        spec.env = std::env::vars().filter(|(name, _)| !name.eq_ignore_ascii_case("NoDefaultCurrentDirectoryInExePath")).collect();
        let quiet = Duration::from_secs(30);
        run("hostname", folder.path(), &spec.env, quiet, &Cancel::new(), &mut |_| {}).await.unwrap();
        if !marker.exists() {
            eprintln!("cmd does not look in the working folder here, so there is nothing to check.");
            return;
        }
        std::fs::remove_file(&marker).unwrap();
        let env = crate::native::agent::environment(&spec);
        assert_eq!(env.get("NoDefaultCurrentDirectoryInExePath").map(String::as_str), Some("1"));
        let ran = run("hostname", folder.path(), &env, quiet, &Cancel::new(), &mut |_| {}).await.unwrap();
        assert_eq!((ran.end, ran.exit), (End::Exited, Some(0)));
        assert!(!marker.exists(), "cmd ran hostname.bat from the working folder");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn a_timeout_stops_a_windows_command() {
        let folder = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let ran = run("ping -n 30 127.0.0.1 > nul", folder.path(), &env(), Duration::from_millis(500), &Cancel::new(), &mut |_| {})
            .await
            .unwrap();
        assert_eq!(ran.end, End::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn capture_keeps_head_and_tail_of_huge_output() {
        let mut capture = Capture::default();
        let chunk = vec![b'a'; 1024 * 1024];
        for _ in 0..12 {
            capture.push(&chunk);
        }
        let (output, dropped) = capture.finish();
        assert_eq!(dropped, 3 * 1024 * 1024);
        assert!(output.len() < HEAD_BYTES + TAIL_BYTES + 16);
    }
}
