//! ACP terminals: commands the agent runs through the client (`terminal/create`), their output
//! bounded as the agent asked, streamed into the tool call that shows the terminal.
use super::super::process;
use super::rpc::{self, RpcError};
use crate::protocol::ToolContent;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;

/// Output kept when the agent names no limit.
const DEFAULT_LIMIT: usize = 1024 * 1024;
/// The most output kept whatever the agent asks.
const MAX_LIMIT: usize = 16 * 1024 * 1024;
/// The output shown in a tool call: the latest part.
const VIEW_LIMIT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitInfo {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl ExitInfo {
    fn json(self) -> Value {
        json!({"exitCode": self.code, "signal": self.signal.map(signal_name)})
    }
}

pub enum TermEvent {
    Output(String),
    Exited(String, ExitInfo),
}

#[derive(Default)]
struct Output {
    text: String,
    truncated: bool,
    limit: usize,
}

impl Output {
    fn push(&mut self, text: &str) {
        self.text.push_str(text);
        if process::keep_tail(&mut self.text, self.limit) {
            self.truncated = true;
        }
    }
}

struct Terminal {
    command: String,
    pid: Option<u32>,
    output: Arc<Mutex<Output>>,
    exit: Option<ExitInfo>,
    waiters: Vec<Value>,
    released: bool,
}

pub struct Terminals {
    map: HashMap<String, Terminal>,
    next: u64,
    sender: mpsc::UnboundedSender<TermEvent>,
    receiver: Option<mpsc::UnboundedReceiver<TermEvent>>,
    /// Terminal id -> the tool calls that show it.
    embeds: HashMap<String, Vec<String>>,
    dirty: HashSet<String>,
}

impl Terminals {
    pub fn new() -> Terminals {
        let (sender, receiver) = mpsc::unbounded_channel();
        Terminals { map: HashMap::new(), next: 0, sender, receiver: Some(receiver), embeds: HashMap::new(), dirty: HashSet::new() }
    }

    /// The stream of output and exit events, taken once by the engine loop.
    pub fn take_events(&mut self) -> mpsc::UnboundedReceiver<TermEvent> {
        self.receiver.take().unwrap_or_else(|| mpsc::unbounded_channel().1)
    }

    /// `terminal/create`: runs the command (through the shell when it comes without arguments).
    pub fn create(&mut self, params: &Value, base_env: &BTreeMap<String, String>, default_cwd: &Path) -> Result<String, RpcError> {
        let command = params["command"]
            .as_str()
            .filter(|c| !c.trim().is_empty())
            .ok_or_else(|| RpcError::new(rpc::INVALID_PARAMS, "terminal/create needs a command."))?;
        let args: Vec<String> = params["args"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_owned)).collect();
        let mut env = base_env.clone();
        for variable in params["env"].as_array().into_iter().flatten() {
            if let (Some(name), Some(value)) = (variable["name"].as_str(), variable["value"].as_str()) {
                env.insert(name.to_owned(), value.to_owned());
            }
        }
        let cwd = match params["cwd"].as_str() {
            Some(dir) if Path::new(dir).is_absolute() => Path::new(dir).to_path_buf(),
            Some(dir) => return Err(RpcError::new(rpc::INVALID_PARAMS, format!("{dir} is not an absolute path."))),
            None => default_cwd.to_path_buf(),
        };
        let limit = params["outputByteLimit"].as_u64().map(|l| (l as usize).clamp(1, MAX_LIMIT)).unwrap_or(DEFAULT_LIMIT);
        let shown = if args.is_empty() { command.to_owned() } else { format!("{command} {}", args.join(" ")) };
        let mut child = build(command, &args, &env, &cwd)
            .spawn()
            .map_err(|e| RpcError::new(rpc::INTERNAL_ERROR, format!("Could not run {shown}: {e}")))?;
        self.next += 1;
        let id = format!("term-{}", self.next);
        let output = Arc::new(Mutex::new(Output { limit, ..Default::default() }));
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(pump(stdout, output.clone(), self.sender.clone(), id.clone()));
        }
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(pump(stderr, output.clone(), self.sender.clone(), id.clone()));
        }
        let pid = child.id();
        let sender = self.sender.clone();
        let done = id.clone();
        tokio::spawn(async move {
            let info = match child.wait().await {
                Ok(status) => exit_info(status),
                Err(_) => ExitInfo { code: None, signal: None },
            };
            let _ = sender.send(TermEvent::Exited(done, info));
        });
        self.map.insert(id.clone(), Terminal { command: shown, pid, output, exit: None, waiters: Vec::new(), released: false });
        Ok(id)
    }

    fn get(&self, id: &str) -> Result<&Terminal, RpcError> {
        self.map.get(id).filter(|t| !t.released).ok_or_else(|| RpcError::new(rpc::RESOURCE_NOT_FOUND, format!("No terminal {id}.")))
    }

    /// `terminal/output`.
    pub fn output(&self, id: &str) -> Result<Value, RpcError> {
        let terminal = self.get(id)?;
        let output = terminal.output.lock().unwrap_or_else(|e| e.into_inner());
        Ok(json!({"output": output.text, "truncated": output.truncated, "exitStatus": terminal.exit.map(ExitInfo::json)}))
    }

    /// `terminal/wait_for_exit`: the result now if it ended, else None and the answer comes
    /// from [`Terminals::exited`].
    pub fn wait(&mut self, id: &str, waiter: Value) -> Result<Option<Value>, RpcError> {
        self.get(id)?;
        let terminal = self.map.get_mut(id).expect("checked");
        match terminal.exit {
            Some(info) => Ok(Some(info.json())),
            None => {
                terminal.waiters.push(waiter);
                Ok(None)
            }
        }
    }

    /// `terminal/kill`: ends the command; its output stays.
    pub fn kill(&mut self, id: &str) -> Result<(), RpcError> {
        let terminal = self.get(id)?;
        if terminal.exit.is_none() {
            if let Some(pid) = terminal.pid {
                process::kill_now(pid);
            }
        }
        Ok(())
    }

    /// `terminal/release`: ends the command if it still runs and frees it; returns waiters to
    /// answer. The last output stays visible in the tool call.
    pub fn release(&mut self, id: &str) -> Vec<(Value, Value)> {
        let Some(terminal) = self.map.get_mut(id) else { return Vec::new() };
        if terminal.released {
            return Vec::new();
        }
        terminal.released = true;
        if terminal.exit.is_none() {
            if let Some(pid) = terminal.pid {
                process::kill_now(pid);
            }
        }
        {
            let mut output = terminal.output.lock().unwrap_or_else(|e| e.into_inner());
            process::keep_tail(&mut output.text, VIEW_LIMIT);
        }
        let result = terminal.exit.unwrap_or(ExitInfo { code: None, signal: Some(9) }).json();
        terminal.waiters.drain(..).map(|w| (w, result.clone())).collect()
    }

    /// Records a command's end; returns waiters to answer.
    pub fn exited(&mut self, id: &str, info: ExitInfo) -> Vec<(Value, Value)> {
        let Some(terminal) = self.map.get_mut(id) else { return Vec::new() };
        terminal.exit = Some(info);
        terminal.waiters.drain(..).map(|w| (w, info.json())).collect()
    }

    /// Notes that a tool call shows this terminal.
    pub fn embed(&mut self, terminal: &str, tool: &str) {
        let tools = self.embeds.entry(terminal.to_owned()).or_default();
        if !tools.iter().any(|t| t == tool) {
            tools.push(tool.to_owned());
        }
    }

    /// The terminal as a tool call shows it.
    pub fn view(&self, id: &str) -> Option<ToolContent> {
        let terminal = self.map.get(id)?;
        let output = terminal.output.lock().unwrap_or_else(|e| e.into_inner());
        let mut text = output.text.clone();
        process::keep_tail(&mut text, VIEW_LIMIT);
        Some(ToolContent::Terminal {
            command: Some(terminal.command.clone()),
            output: text,
            exit_code: terminal.exit.and_then(|e| e.code.or(e.signal.map(|s| 128 + s))),
        })
    }

    pub fn mark(&mut self, id: &str) {
        if self.embeds.contains_key(id) {
            self.dirty.insert(id.to_owned());
        }
    }

    pub fn has_dirty(&self) -> bool {
        !self.dirty.is_empty()
    }

    /// The tool calls whose terminals changed since the last call.
    pub fn take_dirty_tools(&mut self) -> Vec<String> {
        let mut tools = Vec::new();
        for terminal in self.dirty.drain() {
            for tool in self.embeds.get(&terminal).into_iter().flatten() {
                if !tools.contains(tool) {
                    tools.push(tool.clone());
                }
            }
        }
        tools
    }

    /// Ends every command still running (the engine stops).
    pub fn kill_all(&mut self) {
        for terminal in self.map.values() {
            if terminal.exit.is_none() {
                if let Some(pid) = terminal.pid {
                    process::kill_now(pid);
                }
            }
        }
    }
}

fn build(command: &str, args: &[String], env: &BTreeMap<String, String>, cwd: &Path) -> tokio::process::Command {
    let mut cmd = if args.is_empty() {
        shell(command)
    } else {
        let mut cmd = tokio::process::Command::new(process::resolve(command, env));
        cmd.args(args);
        cmd
    };
    cmd.env_clear().envs(env).current_dir(cwd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    #[cfg(unix)]
    cmd.process_group(0);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    cmd
}

#[cfg(unix)]
fn shell(command: &str) -> tokio::process::Command {
    let shell = ["/bin/bash", "/usr/bin/bash"].into_iter().find(|p| Path::new(p).exists()).unwrap_or("/bin/sh");
    let mut cmd = tokio::process::Command::new(shell);
    cmd.arg("-c").arg(command);
    cmd
}

#[cfg(windows)]
fn shell(command: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("cmd");
    cmd.raw_arg("/D").raw_arg("/S").raw_arg("/C").raw_arg(format!("\"{command}\""));
    cmd
}

/// Copies a stream into the terminal's output, keeping UTF-8 sequences whole across reads.
async fn pump<R: AsyncRead + Unpin>(mut stream: R, output: Arc<Mutex<Output>>, sender: mpsc::UnboundedSender<TermEvent>, id: String) {
    let mut buffer = vec![0u8; 16 * 1024];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        let n = match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        pending.extend_from_slice(&buffer[..n]);
        let text = take_utf8(&mut pending);
        if !text.is_empty() {
            output.lock().unwrap_or_else(|e| e.into_inner()).push(&text);
            let _ = sender.send(TermEvent::Output(id.clone()));
        }
    }
    if !pending.is_empty() {
        let text = String::from_utf8_lossy(&pending).into_owned();
        output.lock().unwrap_or_else(|e| e.into_inner()).push(&text);
        let _ = sender.send(TermEvent::Output(id));
    }
}

/// The decodable part of `bytes` as text; an incomplete sequence at the end stays for the next
/// read, and invalid bytes become U+FFFD.
pub fn take_utf8(bytes: &mut Vec<u8>) -> String {
    let mut text = String::new();
    loop {
        match std::str::from_utf8(bytes) {
            Ok(valid) => {
                text.push_str(valid);
                bytes.clear();
                return text;
            }
            Err(error) => {
                let good = error.valid_up_to();
                text.push_str(std::str::from_utf8(&bytes[..good]).expect("valid prefix"));
                match error.error_len() {
                    // Cut in the middle of a character: keep the start for the next read.
                    None => {
                        bytes.drain(..good);
                        return text;
                    }
                    Some(bad) => {
                        text.push('\u{FFFD}');
                        bytes.drain(..good + bad);
                    }
                }
            }
        }
    }
}

fn exit_info(status: std::process::ExitStatus) -> ExitInfo {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        ExitInfo { code: status.code(), signal: status.signal() }
    }
    #[cfg(not(unix))]
    {
        ExitInfo { code: status.code(), signal: None }
    }
}

fn signal_name(signal: i32) -> String {
    match signal {
        1 => "SIGHUP".into(),
        2 => "SIGINT".into(),
        3 => "SIGQUIT".into(),
        6 => "SIGABRT".into(),
        9 => "SIGKILL".into(),
        11 => "SIGSEGV".into(),
        13 => "SIGPIPE".into(),
        15 => "SIGTERM".into(),
        other => format!("SIG{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_split_across_reads_stays_whole() {
        let word = "héllo".as_bytes();
        let mut pending = word[..2].to_vec();
        assert_eq!(take_utf8(&mut pending), "h");
        pending.extend_from_slice(&word[2..]);
        assert_eq!(take_utf8(&mut pending), "éllo");
        let mut bad = vec![b'a', 0xff, b'b'];
        assert_eq!(take_utf8(&mut bad), "a\u{FFFD}b");
    }

    #[test]
    fn output_keeps_its_latest_part_within_the_limit() {
        let mut output = Output { limit: 8, ..Default::default() };
        output.push("0123456789abc");
        assert_eq!(output.text, "56789abc");
        assert!(output.truncated);
        assert_eq!(signal_name(9), "SIGKILL");
    }
}
