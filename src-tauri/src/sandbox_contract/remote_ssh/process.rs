//! M16B: the stock OpenSSH client, run for V12's remote management (VM-W41, the execution
//! half of M16; docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §6.2: bounded
//! calls; VM part §4.5: no secret copies in command arguments; VM-D14: the Jupyter
//! password over authenticated SSH, never in logs or arguments).
//!
//! [`ProcessSshPort`] is the [`SshPort`] that starts the client for one rendered
//! [`SshInvocation`] and reports what it saw, for [`classify`](super::classify). No shell
//! is involved at any point:
//!
//! - Program: the configured absolute path. A bare name or a relative path is refused, so
//!   nothing is looked up on `PATH`. On Windows the path must also be on a local drive
//!   (`C:\...` or the verbatim `\\?\C:\...`), never a share (`\\server\share\...`,
//!   `\\?\UNC\...`), a device path (`\\.\...`) or another verbatim form, and end in
//!   `.exe`: the standard library would try any other path again with `.exe` appended,
//!   and Windows runs a `.bat` or `.cmd` file through the command shell. A drive letter
//!   mapped to a share is not told apart. The arguments after it are exactly
//!   [`SshInvocation::arguments`].
//! - Environment: cleared. On Windows `SystemRoot` and `ProgramData` are passed on,
//!   copied from the engine's. Winsock loads its service providers from paths written as
//!   `%SystemRoot%\system32\...`, and a process without the variable fails to create a
//!   socket (`WSAEPROVIDERFAILEDINIT`). The real Windows OpenSSH client also exits
//!   silently with 255 without `ProgramData`, even with explicit configuration and
//!   key paths. Elsewhere nothing is passed on. No `SSH_AUTH_SOCK`,
//!   `HOME`, `USERPROFILE`, `PATH`, proxy or temporary-directory variable reaches the
//!   client, and with `-F none` it reads no configuration file. Every file it needs is
//!   named in the argv by an [`SshFilePath`](super::SshFilePath), which on Windows starts
//!   with a drive, so the engine and the client resolve it to the same file whatever the
//!   client's working directory. The two-variable Windows environment was verified
//!   against the installed OpenSSH client and a disposable loopback SSH server.
//! - Working directory: the dedicated directory the caller supplies, an absolute path (on
//!   a local drive on Windows, as for the program), checked when the port is made and
//!   again before every start to be a directory in which no entry answers to the name
//!   `none` (a lookup, so letter case follows the file system), so a client that reads
//!   `GlobalKnownHostsFile=none` as a file name finds nothing. The check and the start are
//!   not one atomic step: the directory must be one only the caller writes.
//! - Stdin: the invocation's
//!   [`StdinPayload`](crate::sandbox_contract::remote::StdinPayload) is written once by a
//!   thread of its own, then stdin is closed; without a payload stdin is the null device.
//!   The thread's copy of the payload is overwritten when it is done with it, best effort
//!   (§4.5: zeroization proves nothing about other copies).
//! - Output: stdout and stderr are each read by a thread of their own, at most one byte
//!   more than the stream's bound. Once a stream passes its bound the client is killed and
//!   the run reported with [`SshTermination::NoExitStatus`] (or the exit status the client
//!   already had) and the stream at one byte over the bound, which `classify` reads as
//!   [`SshOutcome::OutputOverBound`](super::SshOutcome::OutputOverBound).
//! - End: the client's end is watched on its own, not through its pipes. Once it has
//!   ended, the readers get at most [`OUTPUT_DRAIN_WAIT`] to read what is left, and the
//!   end is reported with the output read so far: a pipe held open by another process
//!   (which the client should not have started) delays the report by that bound, not by
//!   the deadline, and what that process writes is not read. The bounds hold while
//!   draining.
//! - Deadline: the limits' deadline on the monotonic clock from the start. A client still
//!   running past it is killed and the run reported as [`SshTermination::DeadlineReached`],
//!   whatever it printed.
//! - Start and status: a working directory that no longer qualifies, or a program the
//!   system cannot start, reports [`SshTermination::NotStarted`] and nothing is sent;
//!   [`ProcessSshPort::last_refusal`] says why. A client that ended reports
//!   [`SshTermination::Exited`] with its exit code as the system gives it. On Unix a client
//!   ended by a signal has no code and reports [`SshTermination::NoExitStatus`]. On
//!   Windows every end has a code, so a client killed by another process reports
//!   `Exited` with the killer's code (1 from the standard library's kill), and
//!   `NoExitStatus` comes only from the port's own kill at an output bound.
//! - Local faults: a missing pipe, a thread that cannot start, a failed read of an output
//!   stream or a failed wait on the client kills the client and reports
//!   [`SshTermination::PortFailed`] with the [`PortFailure`](super::PortFailure), which
//!   `classify` reads as uncertain (V12's `AmbiguousResponse`: the command may have run
//!   and its result was not read), never as a lost connection.
//!
//! Containment. PX1's job object (`foundation::process::HostProcess`) is not used: its
//! `ProcessRole` binds every process it starts to a VM boot or a model activation, the
//! client is neither, and a role of its own would mean editing PX1; copying PX1's job code
//! here would duplicate it. The port therefore kills the client process itself
//! (`TerminateProcess` on Windows, `SIGKILL` elsewhere) and waits up to [`REAP_WAIT`] for
//! it to end. That ends all of it, because the rendered argv leaves the client nothing to
//! start: `ProxyCommand=none` and `ProxyJump=none` (no proxy process),
//! `PermitLocalCommand=no` (no local command), `ControlMaster=no` and `ControlPath=none`
//! (no multiplexing master forked into the background), `BatchMode=yes` (no askpass
//! program), `-F none` (no `KnownHostsCommand`) and public-key authentication only (no
//! `ssh-keysign`). From memory of the client sources, not tested: a FIDO security-key
//! identity would start `ssh-sk-helper`, which ends when the client does; the management
//! key is a plain key file. The call itself never waits on a thread: a thread still
//! blocked on a pipe when the run is reported is left to end when that pipe closes.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt as _;

use serde::Serialize;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

use super::invocation::{SshInvocation, SshLimits};
use super::outcome::{OutputStream, PortFailure, SshOutput, SshPort, SshTermination};
use crate::sandbox_contract::remote::StdinPayload;

/// The name a client may open in its working directory for `GlobalKnownHostsFile=none`.
pub const NONE_ENTRY: &str = "none";

/// The variables the client's environment may hold, each copied from the engine's when
/// set: `SystemRoot` and `ProgramData` on Windows, nothing elsewhere.
#[cfg(windows)]
pub const CLIENT_ENVIRONMENT: &[&str] = &["SystemRoot", "ProgramData"];
/// The variables the client's environment may hold: none on this platform.
#[cfg(not(windows))]
pub const CLIENT_ENVIRONMENT: &[&str] = &[];

/// How long a client killed at the deadline or at an output bound, and its output
/// streams, are waited for before the run is reported.
pub const REAP_WAIT: Duration = Duration::from_secs(5);

/// How long the output streams are read after the client has ended, before its end is
/// reported with the output read so far.
pub const OUTPUT_DRAIN_WAIT: Duration = Duration::from_secs(2);

/// How often a running client is looked at.
const POLL: Duration = Duration::from_millis(10);

/// The largest single read from an output stream.
const CHUNK_BYTES: usize = 16 * 1024;

/// Why a client program or working directory was refused, or a client was not started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum SshClientRefusal {
    /// The client program is not an absolute path; nothing is looked up on `PATH`.
    ProgramNotAbsolute,
    /// On Windows, the client program is not on a local drive: a share, a device path or
    /// a verbatim path without a drive.
    ProgramNotOnLocalDrive,
    /// On Windows, the client program does not end in `.exe`; any other path would be
    /// looked up again with `.exe` appended, or run through the command shell.
    ProgramNotExe,
    /// The working directory is not an absolute path.
    WorkingDirectoryNotAbsolute,
    /// On Windows, the working directory is not on a local drive.
    WorkingDirectoryNotOnLocalDrive,
    /// Nothing exists at the working directory's path.
    WorkingDirectoryMissing,
    /// The working directory's path names something other than a directory.
    WorkingDirectoryNotADirectory,
    /// An entry in the working directory answers to the name `none`, which a client could
    /// read as its global known-hosts file.
    NoneEntryInWorkingDirectory,
    /// The working directory could not be inspected.
    WorkingDirectoryUnreadable { error: String },
    /// The system could not start the client program; nothing was sent.
    StartFailed { error: String },
}

impl fmt::Display for SshClientRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProgramNotAbsolute => {
                f.write_str("the ssh client program must be an absolute path")
            }
            Self::ProgramNotOnLocalDrive => {
                f.write_str("the ssh client program must be on a local drive, not a share")
            }
            Self::ProgramNotExe => f.write_str("the ssh client program must be an .exe file"),
            Self::WorkingDirectoryNotAbsolute => {
                f.write_str("the ssh client's working directory must be an absolute path")
            }
            Self::WorkingDirectoryNotOnLocalDrive => f.write_str(
                "the ssh client's working directory must be on a local drive, not a share",
            ),
            Self::WorkingDirectoryMissing => {
                f.write_str("the ssh client's working directory does not exist")
            }
            Self::WorkingDirectoryNotADirectory => {
                f.write_str("the ssh client's working directory is not a directory")
            }
            Self::NoneEntryInWorkingDirectory => f.write_str(
                "the ssh client's working directory holds an entry named 'none', which the \
                 client could read as a known-hosts file",
            ),
            Self::WorkingDirectoryUnreadable { error } => {
                write!(
                    f,
                    "the ssh client's working directory cannot be read: {error}"
                )
            }
            Self::StartFailed { error } => write!(f, "the ssh client could not start: {error}"),
        }
    }
}

impl std::error::Error for SshClientRefusal {}

fn unreadable(error: &io::Error) -> SshClientRefusal {
    SshClientRefusal::WorkingDirectoryUnreadable {
        error: error.to_string(),
    }
}

/// Whether `path` starts with a local drive: `C:\` or `\\?\C:\`, not a share
/// (`\\server\share`, `\\?\UNC\...`), a device (`\\.\...`) or another verbatim prefix.
/// Elsewhere every absolute path qualifies.
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

/// Checks that `program` is an absolute path and, on Windows, an `.exe` on a local
/// drive.
pub(super) fn check_program(program: &Path) -> Result<(), SshClientRefusal> {
    if !program.is_absolute() {
        return Err(SshClientRefusal::ProgramNotAbsolute);
    }
    if !on_local_drive(program) {
        return Err(SshClientRefusal::ProgramNotOnLocalDrive);
    }
    #[cfg(windows)]
    if !program
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return Err(SshClientRefusal::ProgramNotExe);
    }
    Ok(())
}

/// Checks that `directory` is an absolute path (on a local drive on Windows) to a
/// directory where nothing answers to [`NONE_ENTRY`].
pub(super) fn check_working_directory(directory: &Path) -> Result<(), SshClientRefusal> {
    if !directory.is_absolute() {
        return Err(SshClientRefusal::WorkingDirectoryNotAbsolute);
    }
    if !on_local_drive(directory) {
        return Err(SshClientRefusal::WorkingDirectoryNotOnLocalDrive);
    }
    let metadata = std::fs::metadata(directory).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => SshClientRefusal::WorkingDirectoryMissing,
        _ => unreadable(&error),
    })?;
    if !metadata.is_dir() {
        return Err(SshClientRefusal::WorkingDirectoryNotADirectory);
    }
    // The same lookup the client would make, so the file system's own letter-case rules
    // apply; a link named `none` counts whatever it points at.
    match std::fs::symlink_metadata(directory.join(NONE_ENTRY)) {
        Ok(_) => Err(SshClientRefusal::NoneEntryInWorkingDirectory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(unreadable(&error)),
    }
}

/// The command that starts `program` with exactly `arguments` in `working_directory`:
/// the environment cleared but for [`CLIENT_ENVIRONMENT`], stdin piped when a payload
/// follows (the null device otherwise), both output streams piped, and no console window.
pub(super) fn client_command(
    program: &Path,
    working_directory: &Path,
    arguments: &[String],
    stdin_payload: bool,
) -> Command {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .current_dir(working_directory)
        .stdin(if stdin_payload {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in CLIENT_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    // No console window flashes when the engine has none.
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

/// The [`SshPort`] that runs the stock OpenSSH client; see the module notes.
#[derive(Debug)]
pub struct ProcessSshPort {
    program: PathBuf,
    working_directory: PathBuf,
    last_refusal: Option<SshClientRefusal>,
}

impl ProcessSshPort {
    /// The client at `program`, an absolute path (on Windows an `.exe` on a local
    /// drive), run in `working_directory`, an absolute path (on a local drive on Windows)
    /// to an existing directory where nothing answers to the name `none`. The program file
    /// is not looked at until a run starts it.
    pub fn new(
        program: impl Into<PathBuf>,
        working_directory: impl Into<PathBuf>,
    ) -> Result<Self, SshClientRefusal> {
        let program = program.into();
        check_program(&program)?;
        let working_directory = working_directory.into();
        check_working_directory(&working_directory)?;
        Ok(Self {
            program,
            working_directory,
            last_refusal: None,
        })
    }

    /// The client program, as configured; it is started by this path exactly.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The directory the client runs in, checked before every start.
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    /// Why the last run reported [`SshTermination::NotStarted`]; `None` after a run that
    /// started the client.
    pub fn last_refusal(&self) -> Option<&SshClientRefusal> {
        self.last_refusal.as_ref()
    }

    fn command(&self, invocation: &SshInvocation<'_>) -> Command {
        client_command(
            &self.program,
            &self.working_directory,
            invocation.arguments(),
            invocation.stdin().is_some(),
        )
    }

    fn not_started(&mut self, refusal: SshClientRefusal) -> SshOutput {
        self.last_refusal = Some(refusal);
        SshOutput {
            termination: SshTermination::NotStarted,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }
}

impl SshPort for ProcessSshPort {
    fn run(&mut self, invocation: &SshInvocation<'_>) -> SshOutput {
        self.last_refusal = None;
        if let Err(refusal) = check_working_directory(&self.working_directory) {
            return self.not_started(refusal);
        }
        let started = Instant::now();
        match self.command(invocation).spawn() {
            Ok(child) => supervise(child, invocation.limits(), invocation.stdin(), started),
            Err(error) => self.not_started(SshClientRefusal::StartFailed {
                error: error.to_string(),
            }),
        }
    }
}

/// What a reader thread reports.
enum Event {
    /// Bytes read from the stream, in order.
    Output(OutputStream, Vec<u8>),
    /// The reader is done: the stream closed or reached its cap (`failed` false), or a
    /// read failed, so the output was not seen whole (`failed` true).
    Ended { failed: bool },
}

/// The payload copy the stdin thread writes, overwritten when dropped, best effort.
pub(super) struct PayloadCopy(pub(super) Vec<u8>);

impl Drop for PayloadCopy {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

/// Reads `pipe` until it closes or `cap` bytes were read, sending what it reads, then
/// [`Event::Ended`].
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
    // The pipe closes when this thread ends, whether or not the client is still writing.
    let _ = events.send(Event::Ended { failed });
}

/// Starts a reader for one output stream, capped at one byte over `max_bytes`; false
/// when the thread could not start.
fn spawn_reader(
    stream: OutputStream,
    pipe: impl Read + Send + 'static,
    max_bytes: u64,
    events: &Sender<Event>,
) -> bool {
    let events = events.clone();
    thread::Builder::new()
        .name("ssh-client-output".to_owned())
        .spawn(move || read_stream(stream, pipe, max_bytes.saturating_add(1), &events))
        .is_ok()
}

/// Starts the thread that writes the payload once and closes stdin; false when it could
/// not start. A client that ends or closes its stdin first ends the write early; its exit
/// status says what became of the command.
fn spawn_writer(mut pipe: ChildStdin, payload: PayloadCopy) -> bool {
    thread::Builder::new()
        .name("ssh-client-stdin".to_owned())
        .spawn(move || {
            let _ = pipe.write_all(&payload.0);
            drop(pipe);
            drop(payload);
        })
        .is_ok()
}

/// The termination an exit status reports.
fn exit_termination(status: ExitStatus) -> SshTermination {
    status.code().map_or(SshTermination::NoExitStatus, |code| {
        SshTermination::Exited { code }
    })
}

fn port_failed(failure: PortFailure) -> SshTermination {
    SshTermination::PortFailed { failure }
}

/// Whether `stream` holds more than `max_bytes`.
fn over(stream: &[u8], max_bytes: u64) -> bool {
    u64::try_from(stream.len()).map_or(true, |length| length > max_bytes)
}

/// A started client and what has been read from it.
struct Session {
    child: Child,
    limits: SshLimits,
    events: Receiver<Event>,
    readers: usize,
    read_failed: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Starts the threads that feed the client and read it; the local fault, if one could
/// not start.
fn start_threads(
    child: &mut Child,
    limits: SshLimits,
    stdin: Option<&StdinPayload>,
    sender: &Sender<Event>,
    readers: &mut usize,
) -> Result<(), PortFailure> {
    let mut fault = None;
    let mut note = |started: Option<bool>| match started {
        Some(true) => {}
        Some(false) => fault = fault.or(Some(PortFailure::ThreadNotStarted)),
        None => fault = fault.or(Some(PortFailure::PipeMissing)),
    };
    let stdout = child.stdout.take().map(|pipe| {
        spawn_reader(
            OutputStream::Stdout,
            pipe,
            limits.max_stdout_bytes(),
            sender,
        )
    });
    *readers += usize::from(stdout == Some(true));
    note(stdout);
    let stderr = child.stderr.take().map(|pipe| {
        spawn_reader(
            OutputStream::Stderr,
            pipe,
            limits.max_stderr_bytes(),
            sender,
        )
    });
    *readers += usize::from(stderr == Some(true));
    note(stderr);
    if let Some(payload) = stdin {
        let copy = PayloadCopy(payload.expose_to_transport().to_vec());
        note(child.stdin.take().map(|pipe| spawn_writer(pipe, copy)));
    }
    fault.map_or(Ok(()), Err)
}

/// Feeds the client its stdin, reads its output and watches for its end, the deadline or
/// an output bound, whichever comes first.
pub(super) fn supervise(
    mut child: Child,
    limits: SshLimits,
    stdin: Option<&StdinPayload>,
    started: Instant,
) -> SshOutput {
    let (sender, events) = mpsc::channel();
    let mut readers = 0;
    let threads = start_threads(&mut child, limits, stdin, &sender, &mut readers);
    drop(sender);
    let mut session = Session {
        child,
        limits,
        events,
        readers,
        read_failed: false,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    if let Err(failure) = threads {
        return session.stop(port_failed(failure));
    }
    // A deadline past the clock's range cannot be kept, so it is taken as passed.
    let deadline = started
        .checked_add(session.limits.deadline())
        .unwrap_or(started);
    // The client's status and when it was seen, once it has ended.
    let mut ended: Option<(ExitStatus, Instant)> = None;
    loop {
        if session.over_bound() {
            // The client may have ended with a status of its own just before.
            let termination = match ended {
                Some((status, _)) => exit_termination(status),
                None => match session.child.try_wait() {
                    Ok(Some(status)) => exit_termination(status),
                    _ => SshTermination::NoExitStatus,
                },
            };
            return session.stop(termination);
        }
        if ended.is_none() {
            match session.child.try_wait() {
                Ok(Some(status)) => ended = Some((status, Instant::now())),
                Ok(None) => {}
                Err(_) => return session.stop(port_failed(PortFailure::WaitFailed)),
            }
        }
        let now = Instant::now();
        let until = match ended {
            // Ended, and the output read to its end or drained for the bound.
            Some((status, seen)) => {
                let drained = seen.checked_add(OUTPUT_DRAIN_WAIT).unwrap_or(seen);
                if session.readers == 0 || now >= drained {
                    let termination = if session.read_failed {
                        port_failed(PortFailure::ReadFailed)
                    } else {
                        exit_termination(status)
                    };
                    return session.finish(termination);
                }
                drained
            }
            None => {
                if now >= deadline {
                    return session.stop(SshTermination::DeadlineReached);
                }
                deadline
            }
        };
        session.wait_for_event(POLL.min(until.saturating_duration_since(now)));
    }
}

impl Session {
    fn over_bound(&self) -> bool {
        over(&self.stdout, self.limits.max_stdout_bytes())
            || over(&self.stderr, self.limits.max_stderr_bytes())
    }

    /// Takes one reader event, waiting at most `within`; sleeps instead once every
    /// reader is done.
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

    /// Kills the client, waits at most [`REAP_WAIT`] for it to end and for its output to
    /// be read to the end, and reports `termination`.
    fn stop(mut self, termination: SshTermination) -> SshOutput {
        // An error means the client has already ended, or cannot be killed; either way
        // the wait below is bounded.
        let _ = self.child.kill();
        let until = Instant::now()
            .checked_add(REAP_WAIT)
            .unwrap_or_else(Instant::now);
        loop {
            let client_done = !matches!(self.child.try_wait(), Ok(None));
            if client_done && self.readers == 0 {
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

    fn finish(self, termination: SshTermination) -> SshOutput {
        SshOutput {
            termination,
            stdout: self.stdout,
            stderr: self.stderr,
        }
    }
}
