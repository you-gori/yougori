//! The runpodctl process port (VM-W39; VM part §4.5: no secret in command arguments;
//! §6.2: bounded calls).
//!
//! [`RunpodctlPort`] runs one [`RunpodctlInvocation`] and reports what runpodctl did, in
//! the shape `remote_ssh`'s ports report ([`SshOutput`]). [`ProcessRunpodctl`] is the one
//! that starts the program. No shell is involved at any point:
//!
//! - Program: the configured absolute path of Yougori's own reviewed install
//!   (neocloud's `install::installed_program("runpod")`), never a `runpodctl` found on
//!   `PATH`. On Windows it must be an `.exe` on a local drive, for the reasons
//!   `remote_ssh::process` gives (no `.exe` appended and looked up again, no `.bat` run
//!   through the command shell, no share).
//! - Arguments: exactly [`RunpodctlInvocation::arguments`].
//! - Environment: cleared, then [`INHERITED_ENVIRONMENT`] copied from the engine's
//!   (`SystemRoot` on Windows, which Winsock needs to create a socket; nothing
//!   elsewhere), the account key as [`API_KEY_VARIABLE`], `NO_COLOR=1` and `TERM=dumb`
//!   as neocloud passes them, and [`HOME_VARIABLE`] set to the dedicated directory the
//!   caller supplies, which is also the working directory. runpodctl looks for its
//!   configuration under the home directory, so a person's own `~/.runpod` file, which
//!   may hold another account's key, is never read, and a runpodctl that insists on a
//!   home directory still starts. That runpodctl needs nothing more, and reads the key
//!   from the environment ahead of any file, is reasoned from neocloud's use and from Go
//!   programs, not observed: it must be checked against the real program (E01).
//! - Stdin: the null device. Nothing runpodctl is asked needs input.
//! - Output: stdout and stderr each read by a thread of their own, at most one byte over
//!   the invocation's bound. Once a stream passes its bound runpodctl is killed and the
//!   run reported with the stream one byte over the bound, which the transport never
//!   parses.
//! - End and deadline: as `remote_ssh`'s `supervise`, which this port would call if it
//!   were visible here: the program's end is watched apart from its pipes, the readers
//!   get [`OUTPUT_DRAIN_WAIT`] after it, and a program still running at the deadline is
//!   killed and reported as [`SshTermination::DeadlineReached`]. A kill is waited for at
//!   most [`REAP_WAIT`]. runpodctl starts no helper process, so killing it ends the call.
//! - Faults: a home directory that no longer qualifies, a key that is not environment
//!   text or a program the system cannot start reports [`SshTermination::NotStarted`]
//!   (nothing was sent; [`ProcessRunpodctl::last_refusal`] says why); a missing pipe, a
//!   thread that cannot start or a failed read or wait reports
//!   [`SshTermination::PortFailed`].
//!
//! The key exists only in the child's environment block: it is in no argument, in no
//! refusal, and the [`Command`] holding it, whose `Debug` would print it, is never
//! formatted.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt as _;

use serde::Serialize;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

use super::command::{RunpodctlInvocation, RunpodctlLimits};
use super::secret::{key_text, API_KEY_VARIABLE};
use crate::sandbox_contract::provider::SecretValue;
use crate::sandbox_contract::remote_ssh::{
    OutputStream, PortFailure, SshOutput, SshTermination, OUTPUT_DRAIN_WAIT, REAP_WAIT,
};

/// What runpodctl did, in `remote_ssh`'s port shape: how it ended and its output, each
/// stream cut at one byte over its bound.
pub type RunpodctlOutput = SshOutput;

/// Runs runpodctl. [`ProcessRunpodctl`] starts the program; the transport's tests use a
/// fake that plays a RunPod account.
///
/// An implementation runs runpodctl once with exactly [`RunpodctlInvocation::arguments`],
/// passes `key` only in the environment as [`API_KEY_VARIABLE`] and nowhere else, stops it
/// at the invocation's deadline, and reads at most one byte more than each output bound.
pub trait RunpodctlPort {
    fn run(&mut self, invocation: &RunpodctlInvocation, key: &SecretValue) -> RunpodctlOutput;
}

/// The variables copied from the engine's environment when set: `SystemRoot` on Windows.
#[cfg(windows)]
pub const INHERITED_ENVIRONMENT: &[&str] = &["SystemRoot"];
/// The variables copied from the engine's environment: none on this platform.
#[cfg(not(windows))]
pub const INHERITED_ENVIRONMENT: &[&str] = &[];

/// The variable naming the home directory: `USERPROFILE` on Windows.
#[cfg(windows)]
pub const HOME_VARIABLE: &str = "USERPROFILE";
/// The variable naming the home directory: `HOME` on this platform.
#[cfg(not(windows))]
pub const HOME_VARIABLE: &str = "HOME";

/// The fixed variables neocloud passes, so no colour or terminal control reaches the
/// output.
pub const FIXED_ENVIRONMENT: &[(&str, &str)] = &[("NO_COLOR", "1"), ("TERM", "dumb")];

/// How often a running program is looked at.
const POLL: Duration = Duration::from_millis(10);

/// The largest single read from an output stream.
const CHUNK_BYTES: usize = 16 * 1024;

/// Why the program or its directory was refused, or the program was not started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum RunpodctlRefusal {
    /// The program is not an absolute path; nothing is looked up on `PATH`.
    ProgramNotAbsolute,
    /// On Windows, the program is not on a local drive.
    ProgramNotOnLocalDrive,
    /// On Windows, the program does not end in `.exe`.
    ProgramNotExe,
    /// The home directory is not an absolute path.
    HomeNotAbsolute,
    /// On Windows, the home directory is not on a local drive.
    HomeNotOnLocalDrive,
    /// Nothing exists at the home directory's path.
    HomeMissing,
    /// The home directory's path names something other than a directory.
    HomeNotADirectory,
    /// The home directory could not be inspected.
    HomeUnreadable { error: String },
    /// The key is not environment text (see [`key_text`]); it is not shown.
    KeyNotText,
    /// The system could not start the program; nothing was sent.
    StartFailed { error: String },
}

impl std::fmt::Display for RunpodctlRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProgramNotAbsolute => f.write_str("runpodctl must be named by an absolute path"),
            Self::ProgramNotOnLocalDrive => {
                f.write_str("runpodctl must be on a local drive, not a share")
            }
            Self::ProgramNotExe => f.write_str("runpodctl must be an .exe file"),
            Self::HomeNotAbsolute => {
                f.write_str("runpodctl's home directory must be an absolute path")
            }
            Self::HomeNotOnLocalDrive => {
                f.write_str("runpodctl's home directory must be on a local drive, not a share")
            }
            Self::HomeMissing => f.write_str("runpodctl's home directory does not exist"),
            Self::HomeNotADirectory => f.write_str("runpodctl's home directory is not a directory"),
            Self::HomeUnreadable { error } => {
                write!(f, "runpodctl's home directory cannot be read: {error}")
            }
            Self::KeyNotText => f.write_str("the RunPod account key is not usable as text"),
            Self::StartFailed { error } => write!(f, "runpodctl could not start: {error}"),
        }
    }
}

impl std::error::Error for RunpodctlRefusal {}

/// Whether `path` starts with a local drive (`C:\` or `\\?\C:\`) on Windows; every
/// absolute path elsewhere.
#[cfg(windows)]
fn on_local_drive(path: &Path) -> bool {
    use std::path::{Component, Prefix};
    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn on_local_drive(_path: &Path) -> bool {
    true
}

fn check_program(program: &Path) -> Result<(), RunpodctlRefusal> {
    if !program.is_absolute() {
        return Err(RunpodctlRefusal::ProgramNotAbsolute);
    }
    if !on_local_drive(program) {
        return Err(RunpodctlRefusal::ProgramNotOnLocalDrive);
    }
    #[cfg(windows)]
    if !program
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return Err(RunpodctlRefusal::ProgramNotExe);
    }
    Ok(())
}

fn check_home(home: &Path) -> Result<(), RunpodctlRefusal> {
    if !home.is_absolute() {
        return Err(RunpodctlRefusal::HomeNotAbsolute);
    }
    if !on_local_drive(home) {
        return Err(RunpodctlRefusal::HomeNotOnLocalDrive);
    }
    let metadata = std::fs::metadata(home).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => RunpodctlRefusal::HomeMissing,
        _ => RunpodctlRefusal::HomeUnreadable {
            error: error.to_string(),
        },
    })?;
    if !metadata.is_dir() {
        return Err(RunpodctlRefusal::HomeNotADirectory);
    }
    Ok(())
}

/// The [`RunpodctlPort`] that starts the reviewed runpodctl; see the module notes.
#[derive(Debug)]
pub struct ProcessRunpodctl {
    program: PathBuf,
    home: PathBuf,
    last_refusal: Option<RunpodctlRefusal>,
}

impl ProcessRunpodctl {
    /// runpodctl at `program`, an absolute path (an `.exe` on a local drive on Windows),
    /// with `home`, an existing directory only Yougori writes, as its home and working
    /// directory. The program file is not looked at until a call starts it.
    pub fn new(
        program: impl Into<PathBuf>,
        home: impl Into<PathBuf>,
    ) -> Result<Self, RunpodctlRefusal> {
        let program = program.into();
        check_program(&program)?;
        let home = home.into();
        check_home(&home)?;
        Ok(Self {
            program,
            home,
            last_refusal: None,
        })
    }

    /// The program, started by this path exactly.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The home and working directory, checked before every start.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Why the last call reported [`SshTermination::NotStarted`]; `None` after a call
    /// that started the program.
    pub fn last_refusal(&self) -> Option<&RunpodctlRefusal> {
        self.last_refusal.as_ref()
    }

    /// The command for one call. It holds `key` in its environment, so it is never
    /// formatted.
    pub(super) fn command(&self, invocation: &RunpodctlInvocation, key: &str) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(invocation.arguments())
            .env_clear()
            .current_dir(&self.home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for name in INHERITED_ENVIRONMENT {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        for (name, value) in FIXED_ENVIRONMENT {
            command.env(name, value);
        }
        command.env(HOME_VARIABLE, &self.home);
        command.env(API_KEY_VARIABLE, key);
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);
        command
    }

    fn not_started(&mut self, refusal: RunpodctlRefusal) -> RunpodctlOutput {
        self.last_refusal = Some(refusal);
        SshOutput {
            termination: SshTermination::NotStarted,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }
}

impl RunpodctlPort for ProcessRunpodctl {
    fn run(&mut self, invocation: &RunpodctlInvocation, key: &SecretValue) -> RunpodctlOutput {
        self.last_refusal = None;
        if let Err(refusal) = check_home(&self.home) {
            return self.not_started(refusal);
        }
        let Some(key) = key_text(key) else {
            return self.not_started(RunpodctlRefusal::KeyNotText);
        };
        let started = Instant::now();
        match self.command(invocation, key).spawn() {
            Ok(child) => supervise(child, invocation.limits(), started),
            Err(error) => self.not_started(RunpodctlRefusal::StartFailed {
                error: error.to_string(),
            }),
        }
    }
}

/// What a reader thread reports.
enum Event {
    Output(OutputStream, Vec<u8>),
    /// The stream closed or reached its cap (`failed` false), or a read failed.
    Ended {
        failed: bool,
    },
}

/// Reads `pipe` until it closes or `cap` bytes were read, sending what it reads.
fn read_stream(stream: OutputStream, pipe: impl Read, cap: u64, events: &Sender<Event>) {
    let mut pipe = pipe.take(cap);
    let mut buffer = vec![0; CHUNK_BYTES];
    let failed = loop {
        match pipe.read(&mut buffer) {
            Ok(0) => break false,
            Ok(read) => {
                let chunk = buffer.get(..read).unwrap_or_default().to_vec();
                if events.send(Event::Output(stream, chunk)).is_err() {
                    return;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break true,
        }
    };
    let _ = events.send(Event::Ended { failed });
}

/// Starts a reader capped at one byte over `max_bytes`; false when it could not start.
fn spawn_reader(
    stream: OutputStream,
    pipe: impl Read + Send + 'static,
    max_bytes: u64,
    events: &Sender<Event>,
) -> bool {
    let events = events.clone();
    thread::Builder::new()
        .name("runpodctl-output".to_owned())
        .spawn(move || read_stream(stream, pipe, max_bytes.saturating_add(1), &events))
        .is_ok()
}

fn exit_termination(status: ExitStatus) -> SshTermination {
    status.code().map_or(SshTermination::NoExitStatus, |code| {
        SshTermination::Exited { code }
    })
}

fn over(stream: &[u8], max_bytes: u64) -> bool {
    u64::try_from(stream.len()).map_or(true, |length| length > max_bytes)
}

/// A started program and what has been read from it.
struct Watch {
    child: Child,
    limits: RunpodctlLimits,
    events: Receiver<Event>,
    readers: usize,
    read_failed: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Reads the program's output and watches for its end, the deadline or an output bound,
/// whichever comes first.
pub(super) fn supervise(
    child: Child,
    limits: RunpodctlLimits,
    started: Instant,
) -> RunpodctlOutput {
    let (sender, events) = mpsc::channel();
    let mut watch = Watch {
        child,
        limits,
        events,
        readers: 0,
        read_failed: false,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    let stdout = watch.child.stdout.take().map(|pipe| {
        spawn_reader(
            OutputStream::Stdout,
            pipe,
            limits.max_stdout_bytes(),
            &sender,
        )
    });
    let stderr = watch.child.stderr.take().map(|pipe| {
        spawn_reader(
            OutputStream::Stderr,
            pipe,
            limits.max_stderr_bytes(),
            &sender,
        )
    });
    drop(sender);
    let mut fault = None;
    for started_reader in [stdout, stderr] {
        match started_reader {
            Some(true) => watch.readers += 1,
            Some(false) => fault = fault.or(Some(PortFailure::ThreadNotStarted)),
            None => fault = fault.or(Some(PortFailure::PipeMissing)),
        }
    }
    if let Some(failure) = fault {
        return watch.stop(SshTermination::PortFailed { failure });
    }
    // A deadline past the clock's range cannot be kept, so it is taken as passed.
    let deadline = started.checked_add(limits.deadline()).unwrap_or(started);
    let mut ended: Option<(ExitStatus, Instant)> = None;
    loop {
        if watch.over_bound() {
            let termination = match ended {
                Some((status, _)) => exit_termination(status),
                None => match watch.child.try_wait() {
                    Ok(Some(status)) => exit_termination(status),
                    _ => SshTermination::NoExitStatus,
                },
            };
            return watch.stop(termination);
        }
        if ended.is_none() {
            match watch.child.try_wait() {
                Ok(Some(status)) => ended = Some((status, Instant::now())),
                Ok(None) => {}
                Err(_) => {
                    return watch.stop(SshTermination::PortFailed {
                        failure: PortFailure::WaitFailed,
                    })
                }
            }
        }
        let now = Instant::now();
        let until = match ended {
            Some((status, seen)) => {
                let drained = seen.checked_add(OUTPUT_DRAIN_WAIT).unwrap_or(seen);
                if watch.readers == 0 || now >= drained {
                    let termination = if watch.read_failed {
                        SshTermination::PortFailed {
                            failure: PortFailure::ReadFailed,
                        }
                    } else {
                        exit_termination(status)
                    };
                    return watch.finish(termination);
                }
                drained
            }
            None => {
                if now >= deadline {
                    return watch.stop(SshTermination::DeadlineReached);
                }
                deadline
            }
        };
        watch.wait_for_event(POLL.min(until.saturating_duration_since(now)));
    }
}

impl Watch {
    fn over_bound(&self) -> bool {
        over(&self.stdout, self.limits.max_stdout_bytes())
            || over(&self.stderr, self.limits.max_stderr_bytes())
    }

    /// Takes one reader event, waiting at most `within`; sleeps once every reader is done.
    fn wait_for_event(&mut self, within: Duration) {
        if self.readers == 0 {
            thread::sleep(within);
            return;
        }
        match self.events.recv_timeout(within) {
            Ok(Event::Output(OutputStream::Stdout, bytes)) => self.stdout.extend(bytes),
            Ok(Event::Output(OutputStream::Stderr, bytes)) => self.stderr.extend(bytes),
            Ok(Event::Ended { failed }) => {
                self.readers = self.readers.saturating_sub(1);
                self.read_failed |= failed;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => self.readers = 0,
        }
    }

    /// Kills the program, waits at most [`REAP_WAIT`] for it and its output, and reports
    /// `termination`.
    fn stop(mut self, termination: SshTermination) -> RunpodctlOutput {
        // An error means it already ended or cannot be killed; the wait below is bounded.
        let _ = self.child.kill();
        let until = Instant::now()
            .checked_add(REAP_WAIT)
            .unwrap_or_else(Instant::now);
        loop {
            let done = !matches!(self.child.try_wait(), Ok(None));
            if done && self.readers == 0 {
                break;
            }
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            self.wait_for_event(POLL.min(remaining));
        }
        self.finish(termination)
    }

    fn finish(self, termination: SshTermination) -> RunpodctlOutput {
        SshOutput {
            termination,
            stdout: self.stdout,
            stderr: self.stderr,
        }
    }
}
