//! The fake OpenSSH client of the process port's tests (tests only, Windows): this test
//! executable, started by [`ProcessSshPort`](super::ProcessSshPort) exactly as the real
//! client would be. Nothing here runs `ssh` or opens a socket.
//!
//! PX1's helper processes choose their mode through an environment variable and libtest's
//! own arguments (`--exact <helper test>`). Neither works for a client: the port clears
//! the environment and passes exactly the rendered `ssh` arguments, which libtest refuses
//! (`-F` is not one of its options) before any test runs. The fake therefore starts from a
//! CRT initializer (`.CRT$XCU`), which runs before `main`. When the first two arguments
//! are `-F none`, `PATH` is absent (the port clears it; every cargo run has it) and the
//! working directory holds [`SCRIPT_FILE`], it reads stdin to its end, writes a [`Record`]
//! of what it was given to [`RECORD_FILE`] in that directory, acts out the [`Script`] and
//! exits. Any other start of the executable only reads the command line and the
//! environment, returns at once and runs the tests as usual.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

/// The script file the fake looks for in its working directory.
pub const SCRIPT_FILE: &str = "fake-ssh-script.json";
/// The record the fake writes to its working directory before acting.
pub const RECORD_FILE: &str = "fake-ssh-record.json";
/// The mark a sleeping or flooding fake leaves when nothing stopped it in time.
pub const SURVIVOR_FILE: &str = "fake-ssh-survived";
/// The subdirectory a holder runs in, with its own script, record and survivor mark.
pub const HOLDER_DIRECTORY: &str = "holder";

/// Exit codes of a fake that could not do its part.
const BAD_SCRIPT: i32 = 91;
const STDIN_FAILED: i32 = 92;
const RECORD_FAILED: i32 = 93;
const HOLDER_FAILED: i32 = 94;

/// One output stream of the fake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flooded {
    Stdout,
    Stderr,
}

/// What the fake does after recording.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "act", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum Script {
    /// Prints `stdout` and `stderr` and exits with `code`.
    Exit {
        stdout: String,
        stderr: String,
        code: i32,
    },
    /// Sleeps `seconds`, then leaves [`SURVIVOR_FILE`] and exits with 0.
    Sleep { seconds: u64 },
    /// Writes to one stream without pause for `seconds`, ignoring write errors, then
    /// leaves [`SURVIVOR_FILE`] and exits with 0.
    Flood { stream: Flooded, seconds: u64 },
    /// Starts a holder, another fake that inherits stdout and stderr and sleeps
    /// `holder_seconds` in [`HOLDER_DIRECTORY`], then prints `stdout` and exits with 0
    /// while the holder keeps both pipes open.
    ExitLeavingHolder { stdout: String, holder_seconds: u64 },
}

crate::foundation::strict_serde::strict_tag!(Script, "act");

/// What the fake was given.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The program as the command line names it.
    pub program: String,
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub working_directory: PathBuf,
    pub stdin: Vec<u8>,
}

#[used]
#[link_section = ".CRT$XCU"]
static FAKE_CLIENT_ENTRY: extern "C" fn() = fake_client_entry;

/// Runs before `main`; becomes the fake only when started as the port starts a client.
extern "C" fn fake_client_entry() {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    let started_as_client = arguments.get(1).is_some_and(|word| word == "-F")
        && arguments.get(2).is_some_and(|word| word == "none")
        && std::env::var_os("PATH").is_none();
    if !started_as_client {
        return;
    }
    let Ok(directory) = std::env::current_dir() else {
        return;
    };
    let Ok(script) = std::fs::read(directory.join(SCRIPT_FILE)) else {
        return;
    };
    std::process::exit(act(&arguments, &directory, &script));
}

/// Starts a sleeping fake in [`HOLDER_DIRECTORY`] that inherits this fake's stdout and
/// stderr; false when it could not be set up.
fn start_holder(directory: &Path, seconds: u64) -> bool {
    let holder = directory.join(HOLDER_DIRECTORY);
    let script = serde_json::to_vec(&Script::Sleep { seconds });
    let ready = std::fs::create_dir(&holder).is_ok()
        && script.is_ok_and(|script| std::fs::write(holder.join(SCRIPT_FILE), script).is_ok());
    ready
        && std::env::current_exe().is_ok_and(|program| {
            Command::new(program)
                .args(["-F", "none"])
                .current_dir(&holder)
                .stdin(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .is_ok()
        })
}

fn survive(directory: &Path) -> i32 {
    match std::fs::write(directory.join(SURVIVOR_FILE), b"") {
        Ok(()) => 0,
        Err(_) => RECORD_FAILED,
    }
}

fn act(arguments: &[OsString], directory: &Path, script: &[u8]) -> i32 {
    let Ok(script) = serde_json::from_slice::<Script>(script) else {
        return BAD_SCRIPT;
    };
    let mut stdin = Vec::new();
    if std::io::stdin().lock().read_to_end(&mut stdin).is_err() {
        return STDIN_FAILED;
    }
    let mut words = arguments
        .iter()
        .map(|word| word.to_string_lossy().into_owned());
    let record = Record {
        program: words.next().unwrap_or_default(),
        arguments: words.collect(),
        environment: std::env::vars_os()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect(),
        working_directory: directory.to_path_buf(),
        stdin,
    };
    let written = serde_json::to_vec(&record)
        .ok()
        .is_some_and(|json| std::fs::write(directory.join(RECORD_FILE), json).is_ok());
    if !written {
        return RECORD_FAILED;
    }
    match script {
        Script::Exit {
            stdout,
            stderr,
            code,
        } => {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(stdout.as_bytes());
            let _ = out.flush();
            let _ = std::io::stderr().lock().write_all(stderr.as_bytes());
            code
        }
        Script::Sleep { seconds } => {
            thread::sleep(Duration::from_secs(seconds));
            survive(directory)
        }
        Script::Flood { stream, seconds } => {
            let chunk = vec![b'x'; 64 * 1024];
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(seconds) {
                let written = match stream {
                    Flooded::Stdout => std::io::stdout().lock().write_all(&chunk),
                    Flooded::Stderr => std::io::stderr().lock().write_all(&chunk),
                };
                if written.is_err() {
                    thread::sleep(Duration::from_millis(1));
                }
            }
            survive(directory)
        }
        Script::ExitLeavingHolder {
            stdout,
            holder_seconds,
        } => {
            if !start_holder(directory, holder_seconds) {
                return HOLDER_FAILED;
            }
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(stdout.as_bytes());
            let _ = out.flush();
            0
        }
    }
}
