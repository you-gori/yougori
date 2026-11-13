//! Engine child processes: started with only the spec's environment, their stderr kept in a log
//! file with the last lines held for error messages, stopped as a whole process group (SIGTERM,
//! then SIGKILL after a grace period); and line-delimited JSON over their stdio.
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout};
use tokio::sync::{mpsc, watch};

pub mod rpc;

/// Lines of stderr kept for error messages.
pub const TAIL_LINES: usize = 40;
/// The longest stdout line read from an engine (a session update can carry a whole file).
pub const LINE_LIMIT: usize = 32 * 1024 * 1024;
/// How long a stopped process may take to end after SIGTERM before SIGKILL.
pub const STOP_GRACE: Duration = Duration::from_secs(3);
/// A log grows to this size before the next start begins it again.
const LOG_LIMIT: u64 = 8 * 1024 * 1024;
/// Longest single line kept in a tail.
const TAIL_LINE_CHARS: usize = 600;

/// What to start.
pub struct Launch<'a> {
    /// Shown in messages: `OpenCode`, `the HexStrike server`.
    pub name: &'a str,
    /// The log file is `state_dir/<log>.stderr.log`.
    pub log: &'a str,
    pub argv: &'a [String],
    /// The whole environment: nothing else is inherited.
    pub env: &'a BTreeMap<String, String>,
    pub cwd: &'a Path,
    pub state_dir: &'a Path,
    /// Engines talk over stdin and stdout; services get no input and their stdout goes to the log.
    pub stdio: Stdio2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stdio2 {
    /// stdin and stdout piped to us.
    Piped,
    /// No stdin; stdout into the log beside stderr.
    Logged,
}

/// A started process and its pipes.
pub struct Spawned {
    pub guard: ProcessGuard,
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
}

/// The last lines a process wrote, for error messages.
#[derive(Clone, Default)]
pub struct Tail(Arc<Mutex<VecDeque<String>>>);

impl Tail {
    pub fn push(&self, line: &str) {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() {
            return;
        }
        let line: String = if line.chars().count() > TAIL_LINE_CHARS {
            line.chars().take(TAIL_LINE_CHARS).chain("…".chars()).collect()
        } else {
            line.to_owned()
        };
        let mut lines = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if lines.len() == TAIL_LINES {
            lines.pop_front();
        }
        lines.push_back(line);
    }

    /// The kept lines, oldest first.
    pub fn text(&self) -> String {
        let lines = self.0.lock().unwrap_or_else(|e| e.into_inner());
        lines.iter().map(String::as_str).collect::<Vec<_>>().join("\n")
    }

    pub fn is_empty(&self) -> bool {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
    }
}

/// A running child process. Clones share it; when the last clone drops, the process and its whole
/// group are stopped (SIGTERM now, SIGKILL after [`STOP_GRACE`]).
#[derive(Clone)]
pub struct ProcessGuard(Arc<Inner>);

struct Inner {
    name: String,
    pid: Option<u32>,
    status: watch::Receiver<Option<ExitStatus>>,
    stderr: Tail,
    log: PathBuf,
    stopping: AtomicBool,
}

impl ProcessGuard {
    #[cfg(test)]
    pub fn name(&self) -> &str {
        &self.0.name
    }

    /// The process's last stderr lines (and, for services, stdout lines).
    pub fn tail(&self) -> String {
        self.0.stderr.text()
    }

    pub fn log_path(&self) -> &Path {
        &self.0.log
    }

    /// The exit status once the process ended.
    pub fn status(&self) -> Option<ExitStatus> {
        *self.0.status.borrow()
    }

    #[cfg(test)]
    pub fn exited(&self) -> bool {
        self.status().is_some()
    }

    /// Waits until the process ends.
    pub async fn wait(&self) -> Option<ExitStatus> {
        let mut status = self.0.status.clone();
        loop {
            if let Some(done) = *status.borrow_and_update() {
                return Some(done);
            }
            if status.changed().await.is_err() {
                return *status.borrow();
            }
        }
    }

    /// Waits up to `limit` for the process to end.
    pub async fn wait_for(&self, limit: Duration) -> Option<ExitStatus> {
        tokio::time::timeout(limit, self.wait()).await.ok().flatten()
    }

    /// Stops the process and its group: SIGTERM, up to [`STOP_GRACE`] for them to end, SIGKILL.
    pub async fn stop(&self) {
        self.0.stopping.store(true, Ordering::SeqCst);
        let Some(pid) = self.0.pid else { return };
        signal_group(pid, Signal::Term);
        let deadline = tokio::time::Instant::now() + STOP_GRACE;
        let _ = tokio::time::timeout_at(deadline, self.wait()).await;
        // The leader is gone (or out of time); give the rest of its group what is left.
        while tokio::time::Instant::now() < deadline && group_alive(pid) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        signal_group(pid, Signal::Kill);
        let _ = self.wait_for(Duration::from_secs(2)).await;
    }

    /// [`ProcessGuard::stop`] for places that cannot wait asynchronously (drops). Blocks the
    /// calling thread for at most [`STOP_GRACE`] and a little more.
    pub fn stop_blocking(&self) {
        self.0.stopping.store(true, Ordering::SeqCst);
        if let Some(pid) = self.0.pid {
            stop_group_blocking(pid, Some(self.0.status.clone()));
        }
    }

    /// The exit code, or None (still running, or ended by a signal).
    pub fn code(&self) -> Option<i32> {
        self.status().and_then(|s| s.code())
    }

    /// How the process ended, with its last stderr lines and where its whole log is.
    pub fn ended(&self) -> String {
        let how = match self.status() {
            Some(status) => describe(status),
            None => "stopped responding".to_owned(),
        };
        let tail = self.tail();
        let log = self.log_path().display();
        if tail.trim().is_empty() {
            format!("{} {how}. Its log is {log}.", self.0.name)
        } else {
            format!("{} {how}. Its last output (the whole log is {log}):\n{tail}", self.0.name)
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let Some(pid) = self.pid else { return };
        if self.status.borrow().is_some() && !group_alive(pid) {
            return;
        }
        if self.stopping.load(Ordering::SeqCst) && self.status.borrow().is_some() {
            // A stop already ran to its end; only stragglers can be left.
            signal_group(pid, Signal::Kill);
            return;
        }
        signal_group(pid, Signal::Term);
        let status = self.status.clone();
        // Not on this thread: a drop must not hold up the screen for the grace period.
        let _ = std::thread::Builder::new()
            .name("yougori-stop".into())
            .spawn(move || stop_group_blocking(pid, Some(status)));
    }
}

/// How a process ended, in words.
pub fn describe(status: ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("exited with code {code}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return format!("was stopped by signal {signal}");
        }
    }
    "ended".to_owned()
}

#[derive(Clone, Copy)]
enum Signal {
    Term,
    Kill,
}

#[cfg(unix)]
fn signal_group(pid: u32, signal: Signal) {
    let signal = match signal {
        Signal::Term => libc::SIGTERM,
        Signal::Kill => libc::SIGKILL,
    };
    // The child leads its own group (process_group(0)), so this reaches everything it started
    // that did not leave the group.
    unsafe {
        libc::kill(-(pid as libc::pid_t), signal);
    }
}

#[cfg(unix)]
fn group_alive(pid: u32) -> bool {
    unsafe { libc::kill(-(pid as libc::pid_t), 0) == 0 }
}

#[cfg(windows)]
fn signal_group(pid: u32, signal: Signal) {
    // Windows has no SIGTERM: the first request already ends the whole tree.
    let _ = signal;
    let _ = std::process::Command::new("taskkill")
        .args(["/T", "/F", "/PID", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(windows)]
fn group_alive(pid: u32) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

/// Ends a process and everything in its group at once (a terminal the agent kills).
pub fn kill_now(pid: u32) {
    signal_group(pid, Signal::Kill);
}

fn stop_group_blocking(pid: u32, status: Option<watch::Receiver<Option<ExitStatus>>>) {
    signal_group(pid, Signal::Term);
    let deadline = std::time::Instant::now() + STOP_GRACE;
    while std::time::Instant::now() < deadline {
        let leader_done = status.as_ref().map(|s| s.borrow().is_some()).unwrap_or(true);
        if leader_done && !group_alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    signal_group(pid, Signal::Kill);
}

/// Starts a process as [`Launch`] says.
pub async fn spawn(launch: Launch<'_>) -> anyhow::Result<Spawned> {
    let Some(program) = launch.argv.first() else {
        anyhow::bail!("{} has no command.", launch.name);
    };
    std::fs::create_dir_all(launch.state_dir)
        .map_err(|e| anyhow::anyhow!("Cannot create {}: {e}", launch.state_dir.display()))?;
    let log = launch.state_dir.join(format!("{}.stderr.log", file_stem(launch.log)));
    let mut command = tokio::process::Command::new(resolve(program, launch.env));
    command
        .args(&launch.argv[1..])
        .env_clear()
        .envs(launch.env)
        .current_dir(launch.cwd)
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    match launch.stdio {
        Stdio2::Piped => {
            command.stdin(Stdio::piped()).stdout(Stdio::piped());
        }
        Stdio2::Logged => {
            command.stdin(Stdio::null()).stdout(Stdio::piped());
        }
    }
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(windows)]
    command.creation_flags(0x0800_0000); // no console window
    let mut child = command.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!("{} is not installed here ({program} was not found).", launch.name)
        } else {
            anyhow::anyhow!("Could not start {}: {e}", launch.name)
        }
    })?;
    let pid = child.id();
    let tail = Tail::default();
    let file = open_log(&log, launch.name, pid).await;
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(copy_to_log(stderr, file.clone(), tail.clone()));
    }
    let mut stdout = child.stdout.take();
    if launch.stdio == Stdio2::Logged {
        if let Some(out) = stdout.take() {
            tokio::spawn(copy_to_log(out, file.clone(), tail.clone()));
        }
    }
    let stdin = child.stdin.take();
    let (sender, status) = watch::channel(None);
    tokio::spawn(async move {
        let done = child.wait().await.ok();
        let _ = sender.send(done);
    });
    let guard = ProcessGuard(Arc::new(Inner {
        name: launch.name.to_owned(),
        pid,
        status,
        stderr: tail,
        log,
        stopping: AtomicBool::new(false),
    }));
    Ok(Spawned { guard, stdin, stdout })
}

/// The program to run: a bare name is looked up in the child's own PATH, so the engine runs the
/// tool its environment names rather than one on this process's PATH.
pub fn resolve(program: &str, env: &BTreeMap<String, String>) -> PathBuf {
    let path = Path::new(program);
    if path.components().count() > 1 || path.is_absolute() {
        return path.to_path_buf();
    }
    let Some(search) = env.get("PATH") else { return path.to_path_buf() };
    for dir in std::env::split_paths(search) {
        let candidate = dir.join(program);
        if is_program(&candidate) {
            return candidate;
        }
        #[cfg(windows)]
        for ext in ["exe", "cmd", "bat"] {
            let with = candidate.with_extension(ext);
            if with.is_file() {
                return with;
            }
        }
    }
    path.to_path_buf()
}

#[cfg(unix)]
fn is_program(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata().map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

#[cfg(windows)]
fn is_program(path: &Path) -> bool {
    path.is_file()
}

fn file_stem(name: &str) -> String {
    let stem: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '-' })
        .collect();
    let stem = stem.trim_matches('.').to_owned();
    if stem.is_empty() {
        "engine".to_owned()
    } else {
        stem
    }
}

type LogFile = Arc<tokio::sync::Mutex<Option<tokio::fs::File>>>;

async fn open_log(path: &Path, name: &str, pid: Option<u32>) -> LogFile {
    let too_big = tokio::fs::metadata(path).await.map(|m| m.len() > LOG_LIMIT).unwrap_or(false);
    let mut options = tokio::fs::OpenOptions::new();
    options.create(true).write(true);
    if too_big {
        options.truncate(true);
    } else {
        options.append(true);
    }
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await.ok();
    if let Some(f) = file.as_mut() {
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        let header = format!("--- {name} started (pid {}) at unix time {since} ---\n", pid.unwrap_or_default());
        let _ = f.write_all(header.as_bytes()).await;
    }
    Arc::new(tokio::sync::Mutex::new(file))
}

async fn copy_to_log<R: AsyncRead + Unpin>(stream: R, file: LogFile, tail: Tail) {
    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    loop {
        line.clear();
        match read_line(&mut reader, &mut line, 64 * 1024).await {
            Ok(None) => break,
            Ok(Some(_)) => {
                let text = String::from_utf8_lossy(&line);
                tail.push(&text);
                let mut file = file.lock().await;
                if let Some(f) = file.as_mut() {
                    let mut text = text.into_owned();
                    if !text.ends_with('\n') {
                        text.push('\n');
                    }
                    if f.write_all(text.as_bytes()).await.is_err() {
                        *file = None;
                    }
                }
            }
            Err(_) => break,
        }
    }
    if let Some(f) = file.lock().await.as_mut() {
        let _ = f.flush().await;
    }
}

/// Reads one line (without the newline) into `line`, keeping at most `limit` bytes of it.
/// Returns None at the end of the stream, or Some(full length) — longer than `limit` when the
/// line was cut.
pub async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R, line: &mut Vec<u8>, limit: usize) -> std::io::Result<Option<usize>> {
    let mut total = 0usize;
    let mut any = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(if any { Some(total) } else { None });
        }
        any = true;
        let (chunk, found) = match available.iter().position(|b| *b == b'\n') {
            Some(at) => (&available[..at], Some(at)),
            None => (available, None),
        };
        if line.len() < limit {
            let room = limit - line.len();
            line.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
        total += chunk.len();
        let used = found.map(|at| at + 1).unwrap_or(available.len());
        reader.consume(used);
        if found.is_some() {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(total));
        }
    }
}

/// Reads JSON objects, one per line, from an engine's stdout into a channel that closes at the
/// end of the stream. Lines that are not JSON (an engine's log or banner) go into `noise`.
pub fn json_lines<R: AsyncRead + Unpin + Send + 'static>(stream: R, noise: Tail) -> mpsc::UnboundedReceiver<Value> {
    let (sender, receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut reader = BufReader::with_capacity(64 * 1024, stream);
        let mut line = Vec::new();
        loop {
            line.clear();
            match read_line(&mut reader, &mut line, LINE_LIMIT).await {
                Ok(None) | Err(_) => break,
                Ok(Some(length)) if length > LINE_LIMIT => {
                    noise.push(&format!("[a line of {length} bytes was too long and was skipped]"));
                }
                Ok(Some(_)) => {
                    let trimmed = line.trim_ascii();
                    if trimmed.is_empty() {
                        continue;
                    }
                    match serde_json::from_slice::<Value>(trimmed) {
                        Ok(value @ Value::Object(_)) => {
                            if sender.send(value).is_err() {
                                break;
                            }
                        }
                        _ => noise.push(&String::from_utf8_lossy(trimmed)),
                    }
                }
            }
        }
    });
    receiver
}

/// Writes JSON lines to an engine's stdin in order, from any task. Dropping every clone closes
/// the engine's stdin.
#[derive(Clone)]
pub struct LineWriter {
    sender: mpsc::UnboundedSender<Vec<u8>>,
    open: Arc<AtomicBool>,
}

impl LineWriter {
    pub fn new<W: AsyncWrite + Unpin + Send + 'static>(mut stream: W) -> LineWriter {
        let (sender, mut receiver) = mpsc::unbounded_channel::<Vec<u8>>();
        let open = Arc::new(AtomicBool::new(true));
        let flag = open.clone();
        tokio::spawn(async move {
            while let Some(line) = receiver.recv().await {
                // An empty line is the close marker (every line we send ends with a newline).
                if line.is_empty() {
                    break;
                }
                if stream.write_all(&line).await.is_err() || stream.flush().await.is_err() {
                    break;
                }
            }
            flag.store(false, Ordering::SeqCst);
            let _ = stream.shutdown().await;
        });
        LineWriter { sender, open }
    }

    /// Closes the engine's stdin after the lines already queued (an engine may take this as the
    /// sign to end).
    pub fn close(&self) {
        if self.open.swap(false, Ordering::SeqCst) {
            let _ = self.sender.send(Vec::new());
        }
    }

    /// Queues one JSON value as a line. False once the engine's stdin is closed.
    pub fn send(&self, value: &Value) -> bool {
        if !self.open.load(Ordering::SeqCst) {
            return false;
        }
        let mut line = match serde_json::to_vec(value) {
            Ok(line) => line,
            Err(_) => return false,
        };
        line.push(b'\n');
        self.sender.send(line).is_ok()
    }

}

/// The environment of a service: the engine's PATH, home and locale, then the service's own.
pub fn service_environment(engine: &BTreeMap<String, String>, own: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    const BASE: [&str; 9] = ["PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"];
    let mut env: BTreeMap<String, String> =
        engine.iter().filter(|(k, _)| BASE.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
    env.extend(own.iter().map(|(k, v)| (k.clone(), v.clone())));
    env
}

/// Cuts `text` to its last `limit` bytes at a character boundary, for bounded output.
pub fn keep_tail(text: &mut String, limit: usize) -> bool {
    if text.len() <= limit {
        return false;
    }
    let mut start = text.len() - limit;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text.drain(..start);
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// This test binary run again as a child process (see [`child_process`]): its command and
    /// a minimal environment for `mode`.
    pub(crate) fn child(mode: &str) -> (Vec<String>, BTreeMap<String, String>) {
        let argv = vec![
            std::env::current_exe().unwrap().to_string_lossy().into_owned(),
            "--exact".into(),
            "engines::process::tests::child_process".into(),
            "--nocapture".into(),
            "--test-threads".into(),
            "1".into(),
            "-q".into(),
        ];
        let mut env = BTreeMap::new();
        for key in ["PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"] {
            if let Ok(value) = std::env::var(key) {
                env.insert(key.to_owned(), value);
            }
        }
        env.insert("YOUGORI_TEST_CHILD".into(), mode.into());
        (argv, env)
    }

    /// The child: `env` prints what it sees and fails with two stderr lines; `sleep` runs for a
    /// minute; `fail` writes one stderr line and ends with code 2.
    #[test]
    fn child_process() {
        let Ok(mode) = std::env::var("YOUGORI_TEST_CHILD") else { return };
        use std::io::Write;
        match mode.as_str() {
            "env" => {
                let only = std::env::var("ONLY_THIS").unwrap_or_default();
                let leak = std::env::var("YOUGORI_TEST_LEAK").unwrap_or_default();
                let mut out = std::io::stdout();
                writeln!(out, "{}", serde_json::json!({"only": only, "leak": leak})).unwrap();
                out.flush().unwrap();
                eprintln!("first problem");
                eprintln!("second problem");
                std::process::exit(3);
            }
            "sleep" => {
                std::thread::sleep(Duration::from_secs(60));
                std::process::exit(0);
            }
            "fail" => {
                eprintln!("port 8888 is taken");
                std::process::exit(2);
            }
            _ => std::process::exit(9),
        }
    }

    #[tokio::test]
    async fn a_child_gets_only_the_given_environment_and_its_stderr_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("YOUGORI_TEST_LEAK", "leaked");
        let (argv, mut env) = child("env");
        env.insert("ONLY_THIS".into(), "given".into());
        let spawned = spawn(Launch {
            name: "Probe",
            log: "probe",
            argv: &argv,
            env: &env,
            cwd: dir.path(),
            state_dir: &dir.path().join("state"),
            stdio: Stdio2::Piped,
        })
        .await
        .unwrap();
        let noise = Tail::default();
        let mut lines = json_lines(spawned.stdout.unwrap(), noise.clone());
        let first = tokio::time::timeout(Duration::from_secs(20), lines.recv()).await.unwrap().expect("the child printed nothing");
        assert_eq!(first["only"], "given");
        assert_eq!(first["leak"], "", "the parent's environment leaked");
        let status = spawned.guard.wait_for(Duration::from_secs(20)).await.unwrap();
        assert_eq!(status.code(), Some(3));
        // The stderr reader keeps the tail and then writes the log a moment after the exit.
        let path = dir.path().join("state/probe.stderr.log");
        let mut log = String::new();
        for _ in 0..250 {
            log = std::fs::read_to_string(&path).unwrap_or_default();
            if spawned.guard.tail().contains("second problem") && log.contains("second problem") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(spawned.guard.tail().contains("first problem"), "{}", spawned.guard.tail());
        assert!(spawned.guard.ended().contains("exited with code 3"));
        assert!(log.contains("second problem") && log.contains("Probe started"), "{log}");
    }

    #[tokio::test]
    async fn a_stopped_process_ends_and_a_missing_program_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let (argv, env) = child("sleep");
        let spawned = spawn(Launch {
            name: "Sleeper",
            log: "sleeper",
            argv: &argv,
            env: &env,
            cwd: dir.path(),
            state_dir: dir.path(),
            stdio: Stdio2::Logged,
        })
        .await
        .unwrap();
        assert!(!spawned.guard.exited());
        let started = std::time::Instant::now();
        spawned.guard.stop().await;
        assert!(spawned.guard.exited());
        assert!(started.elapsed() < Duration::from_secs(8));

        let missing = vec!["yougori-no-such-program".to_owned()];
        let error = spawn(Launch {
            name: "Nothing",
            log: "nothing",
            argv: &missing,
            env: &env,
            cwd: dir.path(),
            state_dir: dir.path(),
            stdio: Stdio2::Piped,
        })
        .await
        .err()
        .unwrap();
        assert!(format!("{error}").contains("not installed"), "{error}");
    }

    #[tokio::test]
    async fn dropping_the_last_guard_stops_the_process() {
        let dir = tempfile::tempdir().unwrap();
        let (argv, env) = child("sleep");
        let spawned = spawn(Launch {
            name: "Sleeper",
            log: "sleeper",
            argv: &argv,
            env: &env,
            cwd: dir.path(),
            state_dir: dir.path(),
            stdio: Stdio2::Logged,
        })
        .await
        .unwrap();
        let mut watcher = spawned.guard.0.status.clone();
        drop(spawned);
        let ended = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if watcher.borrow_and_update().is_some() {
                    return;
                }
                if watcher.changed().await.is_err() {
                    return;
                }
            }
        })
        .await;
        assert!(ended.is_ok(), "the process still runs");
    }

    #[tokio::test]
    async fn lines_are_split_on_newlines_only_and_long_lines_are_skipped() {
        let (mut write, read) = tokio::io::duplex(1 << 16);
        let noise = Tail::default();
        let mut values = json_lines(read, noise.clone());
        let writer = tokio::spawn(async move {
            write.write_all(b"{\"a\":\"x\\u2028y\"}\r\nnot json\n\n{\"b\":2}\n").await.unwrap();
            let big = format!("{{\"c\":\"{}\"}}\n", "z".repeat(LINE_LIMIT + 10));
            write.write_all(big.as_bytes()).await.unwrap();
            write.write_all(b"{\"d\":4}").await.unwrap();
        });
        assert_eq!(values.recv().await.unwrap()["a"], "x\u{2028}y");
        assert_eq!(values.recv().await.unwrap()["b"], 2);
        assert_eq!(values.recv().await.unwrap()["d"], 4);
        assert!(values.recv().await.is_none());
        writer.await.unwrap();
        let noise = noise.text();
        assert!(noise.contains("not json") && noise.contains("too long"), "{noise}");
    }

    #[tokio::test]
    async fn a_closed_writer_closes_the_stream() {
        let (write, mut read) = tokio::io::duplex(1024);
        let writer = LineWriter::new(write);
        assert!(writer.send(&serde_json::json!({"x": 1})));
        writer.close();
        assert!(!writer.send(&serde_json::json!({"y": 2})));
        let mut all = String::new();
        use tokio::io::AsyncReadExt;
        read.read_to_string(&mut all).await.unwrap();
        assert_eq!(all, "{\"x\":1}\n");
    }

    #[test]
    fn tails_keep_the_last_lines_and_cut_long_ones() {
        let tail = Tail::default();
        for n in 0..(TAIL_LINES + 5) {
            tail.push(&format!("line {n}\n"));
        }
        tail.push(&"x".repeat(2000));
        let text = tail.text();
        assert!(!text.contains("line 0\n") && text.contains("line 44"));
        assert!(text.lines().last().unwrap().ends_with('…'));
        let mut output = "héllo wörld".to_owned();
        assert!(keep_tail(&mut output, 6));
        assert!(output.len() <= 6 && "héllo wörld".ends_with(&output));
    }

    #[test]
    fn services_get_the_engine_basics_and_their_own_variables() {
        let engine = BTreeMap::from([
            ("PATH".to_owned(), "/bin".to_owned()),
            ("HOME".to_owned(), "/home/node".to_owned()),
            ("SECRET_TOKEN".to_owned(), "x".to_owned()),
        ]);
        let own = BTreeMap::from([("PORT".to_owned(), "8000".to_owned())]);
        let env = service_environment(&engine, &own);
        assert_eq!(env.get("PATH").map(String::as_str), Some("/bin"));
        assert_eq!(env.get("PORT").map(String::as_str), Some("8000"));
        assert!(!env.contains_key("SECRET_TOKEN"));
    }
}
