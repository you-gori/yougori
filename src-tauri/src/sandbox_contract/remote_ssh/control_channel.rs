//! M16G: the long-lived OpenSSH client that carries V12's control frames (VM-W39 "loss of
//! control connection"; VM-W41 "remote reconnect cannot revive expired authority";
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §6.3: the authenticated
//! control session; VM part §4.5: no secret copies in command arguments).
//!
//! [`ControlChannel`] is one run of the stock client for one control session, started by
//! [`ControlTransport`](super::ControlTransport) under the rules of
//! [`ProcessSshPort`](super::ProcessSshPort), through the same helpers: the configured
//! absolute program, exactly the rendered arguments of V12's invocation of the control
//! agent, the cleared environment, the checked working directory and no console window.
//! What differs is that the client stays up and both directions stay open.
//!
//! Wire format, both directions: a message is a 4-byte big-endian length, then that many
//! bytes.
//!
//! - Host to remote, on the client's stdin: first the session key, a message of exactly
//!   [`CONTROL_KEY_BYTES`] bytes; then frames.
//! - Remote to host, on the client's stdout: frames only.
//! - A frame is one V12 [`SealedFrame`] as JSON, read strictly (every struct refuses
//!   unknown fields, every tagged enum reads its tag through `foundation::strict_serde`,
//!   and trailing bytes other than JSON whitespace are refused; the seal covers the
//!   frame's fields, not its bytes), of 1 to [`MAX_CONTROL_FRAME_BYTES`] bytes. The
//!   length is checked before anything is allocated: a frame declared longer, or empty,
//!   ends the channel. Anything that is not one strict `SealedFrame` ends it too.
//!
//! Threads, as in `process`: one writes the client's stdin, one reads frames from its
//! stdout and one drains its stderr, all reporting to the channel over one queue; the
//! channel itself never blocks on a pipe. Every wait is bounded:
//!
//! - Writes: [`ControlChannel`] hands a message to the writer and waits at most the
//!   limits' write wait for it to be written; a remote that stops reading stalls the
//!   writes and ends the channel. Each message is held in a buffer overwritten once it is
//!   written or dropped (best effort, as in `process`), so the key leaves no copy in the
//!   channel's own buffers.
//! - Reads: frames arrive whole and within their bound; a receive waits at most the time
//!   it is given.
//! - stderr: drained for the channel's whole life into a buffer of at most one byte over
//!   the limits' stderr bound. Passing the bound ends the channel, so a remote that floods
//!   stderr cannot grow the buffer; stderr is classified only at the end, through
//!   [`classify`], which is how a host-key mismatch the client reports reaches V12.
//! - Silence: the channel ends once no frame has arrived for the limits' silence
//!   deadline, on the monotonic clock, counted from the start, so the remote's first
//!   frame is due within it too.
//! - End: the channel ends when stdout closes (between frames or inside one), when the
//!   client exits (watched apart from its pipes, with [`OUTPUT_DRAIN_WAIT`] for frames
//!   still in the pipe), when a write fails (a broken pipe included), at a stalled write,
//!   at the silence deadline, at a frame out of bounds or malformed, at stderr over its
//!   bound, and at a local fault. Frames already read are handed out before the end is
//!   reported.
//!
//! Closing: stdin is closed, and for an end the client may be finishing by itself (its
//! stdout or stdin closed, it exited, or the host closed the channel) the client gets
//! [`OUTPUT_DRAIN_WAIT`] to exit with its own status, which the classification needs: a
//! host-key failure is the client's exit with 255 and its message on stderr. Otherwise,
//! and after that wait, the client is killed and reaped within [`REAP_WAIT`], as the
//! process port does. The termination reported is the client's own exit status when it
//! had one, the deadline for silence, and no exit status for a client the channel killed.
//! The SSH limits' deadline and stdout bound do not apply to a channel: its life is
//! bounded by the silence deadline, and its stdout by the frame bound.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::control_transport::ControlLimits;
use super::invocation::SshInvocation;
use super::outcome::{classify, PortFailure, SshOutcome, SshOutput, SshTermination};
use super::process::{
    check_working_directory, client_command, PayloadCopy, SshClientRefusal, OUTPUT_DRAIN_WAIT,
    REAP_WAIT,
};
use crate::sandbox_contract::remote::{AdapterRefusal, ControlSessionId, SealedFrame};

/// The length of a session key, the first message on the client's stdin.
pub const CONTROL_KEY_BYTES: usize = 32;

/// The largest frame accepted or sent, in bytes after the length prefix. A sealed frame
/// is a few hundred bytes of JSON.
pub const MAX_CONTROL_FRAME_BYTES: u32 = 16 * 1024;

/// The bytes of the big-endian length before every message.
const PREFIX_BYTES: usize = 4;

/// How often the channel looks at the client while it waits.
const POLL: Duration = Duration::from_millis(10);

/// The largest single read of stderr.
const CHUNK_BYTES: usize = 16 * 1024;

/// Why a control channel ended. Every end marks the session lost through V12.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum ControlEndReason {
    /// The client's stdout closed between frames: the remote side or the client ended.
    EndOfStream,
    /// The client's stdout closed inside a frame.
    Truncated,
    /// The client exited.
    ClientExited,
    /// Writing to the client's stdin failed; `broken_pipe` when nothing read it any more.
    WriteFailed { broken_pipe: bool },
    /// A message was not written within the write wait: the remote does not read.
    WriteStalled,
    /// No frame arrived within the silence deadline.
    Silent { silent_for_ms: u64 },
    /// The remote declared a frame of this length, empty or over the bound.
    FrameOutOfBounds { declared: u64, max_bytes: u64 },
    /// A frame is not one strict sealed frame.
    Malformed,
    /// A frame to send could not be encoded within the bound.
    FrameNotEncoded,
    /// V12 refused a frame or a step on this session. Boxed: V12's refusal takes over
    /// 200 bytes.
    Refused { refusal: Box<AdapterRefusal> },
    /// The client's stderr passed its bound.
    StderrOverBound { max_bytes: u64 },
    /// A local fault after the start: a pipe or thread was missing, a read of stdout or
    /// stderr failed, or waiting on the client failed.
    PortFailed { failure: PortFailure },
    /// The host closed the channel.
    Closed,
}

impl ControlEndReason {
    /// Whether the client may be ending by itself, so it is given time to exit with its
    /// own status before it is killed.
    fn may_end_by_itself(&self) -> bool {
        matches!(
            self,
            Self::EndOfStream
                | Self::Truncated
                | Self::ClientExited
                | Self::WriteFailed { .. }
                | Self::Closed
        )
    }
}

impl fmt::Display for ControlEndReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndOfStream => f.write_str("the control channel's output closed"),
            Self::Truncated => f.write_str("the control channel's output closed inside a frame"),
            Self::ClientExited => f.write_str("the ssh client of the control channel exited"),
            Self::WriteFailed { .. } => f.write_str("writing to the control channel failed"),
            Self::WriteStalled => {
                f.write_str("the remote side stopped reading the control channel")
            }
            Self::Silent { silent_for_ms } => write!(
                f,
                "nothing arrived on the control channel for {silent_for_ms} ms"
            ),
            Self::FrameOutOfBounds {
                declared,
                max_bytes,
            } => write!(
                f,
                "the remote declared a control frame of {declared} bytes; frames are 1 to \
                 {max_bytes} bytes"
            ),
            Self::Malformed => f.write_str("the remote sent something other than a sealed frame"),
            Self::FrameNotEncoded => f.write_str("a control frame could not be encoded"),
            Self::Refused { refusal } => write!(f, "{refusal}"),
            Self::StderrOverBound { max_bytes } => write!(
                f,
                "the ssh client of the control channel wrote more than {max_bytes} bytes to \
                 stderr"
            ),
            Self::PortFailed { failure } => {
                write!(f, "the control channel failed locally: {failure:?}")
            }
            Self::Closed => f.write_str("the host closed the control channel"),
        }
    }
}

/// How the client's stdout ended, as its reader saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StdoutEnd {
    EndOfStream,
    Truncated,
    OutOfBounds { declared: u32 },
    ReadFailed,
}

/// What a pipe thread reports.
enum Event {
    /// One whole frame from stdout, within the bound.
    Frame(Vec<u8>),
    StdoutEnded(StdoutEnd),
    /// Bytes read from stderr, in order.
    Stderr(Vec<u8>),
    /// The stderr reader is done: the stream closed or reached its cap (`failed` false),
    /// or a read failed.
    StderrEnded {
        failed: bool,
    },
    /// One message was written to stdin.
    Written,
    WriteFailed {
        broken_pipe: bool,
    },
}

/// How a read of a whole buffer went.
enum Fill {
    Full,
    /// The stream ended before the first byte.
    Empty,
    /// The stream ended inside the buffer.
    Partial,
    Failed,
}

fn fill(pipe: &mut impl Read, buffer: &mut [u8]) -> Fill {
    let mut filled = 0;
    while filled < buffer.len() {
        let Some(rest) = buffer.get_mut(filled..) else {
            return Fill::Failed;
        };
        match pipe.read(rest) {
            Ok(0) if filled == 0 => return Fill::Empty,
            Ok(0) => return Fill::Partial,
            Ok(read) => filled = filled.saturating_add(read),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Fill::Failed,
        }
    }
    Fill::Full
}

/// Reads frames from `pipe` until it ends or breaks the framing; the pipe closes when
/// this returns.
fn read_frames(mut pipe: ChildStdout, events: &Sender<Event>) {
    let end = loop {
        let mut prefix = [0u8; PREFIX_BYTES];
        match fill(&mut pipe, &mut prefix) {
            Fill::Full => {}
            Fill::Empty => break StdoutEnd::EndOfStream,
            Fill::Partial => break StdoutEnd::Truncated,
            Fill::Failed => break StdoutEnd::ReadFailed,
        }
        let declared = u32::from_be_bytes(prefix);
        let length = match usize::try_from(declared) {
            Ok(length) if (1..=MAX_CONTROL_FRAME_BYTES).contains(&declared) => length,
            _ => break StdoutEnd::OutOfBounds { declared },
        };
        let mut frame = vec![0; length];
        match fill(&mut pipe, &mut frame) {
            Fill::Full => {
                if events.send(Event::Frame(frame)).is_err() {
                    return;
                }
            }
            Fill::Empty | Fill::Partial => break StdoutEnd::Truncated,
            Fill::Failed => break StdoutEnd::ReadFailed,
        }
    };
    let _ = events.send(Event::StdoutEnded(end));
}

/// Drains `pipe` until it closes or `cap` bytes were read.
fn drain_stderr(pipe: ChildStderr, cap: u64, events: &Sender<Event>) {
    let mut pipe = pipe.take(cap);
    let mut buffer = vec![0; CHUNK_BYTES];
    let failed = loop {
        match pipe.read(&mut buffer) {
            Ok(0) => break false,
            Ok(read) => {
                let chunk = buffer.get(..read).unwrap_or_default().to_vec();
                if events.send(Event::Stderr(chunk)).is_err() {
                    return;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break true,
        }
    };
    let _ = events.send(Event::StderrEnded { failed });
}

/// Writes each message as it comes, until the channel stops sending or a write fails;
/// stdin closes when this returns. Every message is overwritten once written or dropped.
fn write_messages(mut pipe: ChildStdin, messages: &Receiver<PayloadCopy>, events: &Sender<Event>) {
    for message in messages {
        let written = pipe.write_all(&message.0).and_then(|()| pipe.flush());
        drop(message);
        let event = match written {
            Ok(()) => Event::Written,
            Err(error) => Event::WriteFailed {
                broken_pipe: error.kind() == io::ErrorKind::BrokenPipe,
            },
        };
        let failed = matches!(event, Event::WriteFailed { .. });
        if events.send(event).is_err() || failed {
            return;
        }
    }
}

/// `payload` behind its big-endian length, in a buffer overwritten when dropped; `None`
/// for an empty payload or one over `max_bytes`.
pub(super) fn framed(payload: &[u8], max_bytes: u32) -> Option<PayloadCopy> {
    let length = u32::try_from(payload.len())
        .ok()
        .filter(|length| (1..=max_bytes).contains(length))?;
    let mut message = Vec::with_capacity(payload.len().saturating_add(PREFIX_BYTES));
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(payload);
    Some(PayloadCopy(message))
}

/// `frame` as one message on the wire.
pub(super) fn encode(frame: &SealedFrame) -> Result<PayloadCopy, ControlEndReason> {
    let json = serde_json::to_vec(frame).map_err(|_| ControlEndReason::FrameNotEncoded)?;
    framed(&json, MAX_CONTROL_FRAME_BYTES).ok_or(ControlEndReason::FrameNotEncoded)
}

/// `bytes` as one strict sealed frame.
fn decode(bytes: &[u8]) -> Result<SealedFrame, ControlEndReason> {
    serde_json::from_slice(bytes).map_err(|_| ControlEndReason::Malformed)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn over(stream: &[u8], max_bytes: u64) -> bool {
    u64::try_from(stream.len()).map_or(true, |length| length > max_bytes)
}

/// The termination an exit status reports.
fn exit_termination(status: ExitStatus) -> SshTermination {
    status.code().map_or(SshTermination::NoExitStatus, |code| {
        SshTermination::Exited { code }
    })
}

/// What a closed channel reports: how the client ended, its stderr, and the
/// classification of both under the channel's invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ChannelClosed {
    pub(super) output: SshOutput,
    pub(super) outcome: SshOutcome,
}

/// One running client carrying one control session; see the module notes. Only
/// [`ControlTransport`](super::ControlTransport) starts, drives and closes it. `Debug`
/// shows the session, the client's process id and counts, nothing that was sent.
pub struct ControlChannel<'a> {
    session: ControlSessionId,
    invocation: SshInvocation<'a>,
    limits: ControlLimits,
    child: Child,
    outbound: Option<Sender<PayloadCopy>>,
    events: Receiver<Event>,
    frames: VecDeque<Vec<u8>>,
    stdout_end: Option<StdoutEnd>,
    stderr: Vec<u8>,
    stderr_open: bool,
    fault: Option<PortFailure>,
    pending_writes: usize,
    write_failed: Option<bool>,
    /// The client's status and when it was seen, once it has ended.
    exited: Option<(ExitStatus, Instant)>,
    last_heard: Instant,
}

impl Drop for ControlChannel<'_> {
    /// A channel dropped without being closed (with its transport, say) kills its client;
    /// V12's session then goes silent, and V12 renews nothing over it.
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

impl fmt::Debug for ControlChannel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlChannel")
            .field("session", &self.session)
            .field("client", &self.child.id())
            .field("limits", &self.limits)
            .field("frames_waiting", &self.frames.len())
            .field("pending_writes", &self.pending_writes)
            .field("stderr_bytes", &self.stderr.len())
            .finish_non_exhaustive()
    }
}

impl<'a> ControlChannel<'a> {
    /// Starts `program` in `working_directory` with `invocation`'s arguments, writes
    /// `key` and then `hello` to its stdin, and starts its pipe threads. The working
    /// directory is checked again first; a refusal or a failed start starts nothing.
    pub(super) fn start(
        program: &Path,
        working_directory: &Path,
        session: ControlSessionId,
        invocation: SshInvocation<'a>,
        limits: ControlLimits,
        key: PayloadCopy,
        hello: PayloadCopy,
    ) -> Result<Self, SshClientRefusal> {
        check_working_directory(working_directory)?;
        let mut child = client_command(program, working_directory, invocation.arguments(), true)
            .spawn()
            .map_err(|error| SshClientRefusal::StartFailed {
                error: error.to_string(),
            })?;
        let (sender, events) = mpsc::channel();
        let (outbound, messages) = mpsc::channel::<PayloadCopy>();
        let cap = limits.ssh().max_stderr_bytes().saturating_add(1);
        let stderr = child.stderr.take().map(|pipe| {
            let events = sender.clone();
            thread::Builder::new()
                .name("ssh-control-stderr".to_owned())
                .spawn(move || drain_stderr(pipe, cap, &events))
                .is_ok()
        });
        let stderr_open = stderr == Some(true);
        let mut fault = None;
        let mut note = |started: Option<bool>| match started {
            Some(true) => {}
            Some(false) => fault = fault.or(Some(PortFailure::ThreadNotStarted)),
            None => fault = fault.or(Some(PortFailure::PipeMissing)),
        };
        note(stderr);
        note(child.stdout.take().map(|pipe| {
            let events = sender.clone();
            thread::Builder::new()
                .name("ssh-control-stdout".to_owned())
                .spawn(move || read_frames(pipe, &events))
                .is_ok()
        }));
        note(child.stdin.take().map(|pipe| {
            let events = sender.clone();
            thread::Builder::new()
                .name("ssh-control-stdin".to_owned())
                .spawn(move || write_messages(pipe, &messages, &events))
                .is_ok()
        }));
        drop(sender);
        let mut channel = Self {
            session,
            invocation,
            limits,
            child,
            outbound: Some(outbound),
            events,
            frames: VecDeque::new(),
            stdout_end: None,
            stderr: Vec::new(),
            stderr_open,
            fault,
            pending_writes: 0,
            write_failed: None,
            exited: None,
            last_heard: Instant::now(),
        };
        // Queued now and written by the writer as soon as it runs; a writer that did not
        // start drops them, overwritten, and the fault ends the channel on first use.
        for message in [key, hello] {
            if channel.queue(message).is_err() {
                break;
            }
        }
        Ok(channel)
    }

    /// The control session this channel carries.
    pub fn session(&self) -> ControlSessionId {
        self.session
    }

    /// The process id of the client.
    pub fn client_id(&self) -> u32 {
        self.child.id()
    }

    /// The arguments the client was started with, after the program.
    pub fn arguments(&self) -> &[String] {
        self.invocation.arguments()
    }

    /// Hands `message` to the writer.
    fn queue(&mut self, message: PayloadCopy) -> Result<(), ControlEndReason> {
        let sent = self
            .outbound
            .as_ref()
            .is_some_and(|outbound| outbound.send(message).is_ok());
        if !sent {
            // The writer is gone; it reported why, unless it never started.
            return Err(self.write_end());
        }
        self.pending_writes = self.pending_writes.saturating_add(1);
        Ok(())
    }

    fn write_end(&self) -> ControlEndReason {
        match (self.fault, self.write_failed) {
            (Some(failure), _) => ControlEndReason::PortFailed { failure },
            (None, Some(broken_pipe)) => ControlEndReason::WriteFailed { broken_pipe },
            (None, None) => ControlEndReason::WriteFailed { broken_pipe: false },
        }
    }

    /// Sends `frame` and waits at most the write wait for it, and everything queued
    /// before it, to be written.
    pub(super) fn send(&mut self, frame: &SealedFrame) -> Result<(), ControlEndReason> {
        if let Some(failure) = self.fault {
            return Err(ControlEndReason::PortFailed { failure });
        }
        let message = encode(frame)?;
        self.queue(message)?;
        let started = Instant::now();
        let until = started
            .checked_add(self.limits.write_wait())
            .unwrap_or(started);
        while self.pending_writes > 0 {
            if self.write_failed.is_some() {
                return Err(self.write_end());
            }
            let now = Instant::now();
            if now >= until {
                return Err(ControlEndReason::WriteStalled);
            }
            self.pump(POLL.min(until.saturating_duration_since(now)));
        }
        Ok(())
    }

    /// The next frame, waiting at most `within`; `None` when none arrived and the
    /// channel has not ended. Frames already read come before any end.
    pub(super) fn receive(
        &mut self,
        within: Duration,
    ) -> Result<Option<SealedFrame>, ControlEndReason> {
        let started = Instant::now();
        let until = started.checked_add(within).unwrap_or(started);
        loop {
            if let Some(bytes) = self.frames.pop_front() {
                return decode(&bytes).map(Some);
            }
            let now = Instant::now();
            let silent_until = self.check_end(now)?;
            if now >= until {
                return Ok(None);
            }
            let next = until.min(silent_until);
            self.pump(POLL.min(next.saturating_duration_since(now)));
        }
    }

    /// The end the channel has reached by `now`, if any; otherwise when the silence
    /// deadline falls.
    fn check_end(&mut self, now: Instant) -> Result<Instant, ControlEndReason> {
        if let Some(failure) = self.fault {
            return Err(ControlEndReason::PortFailed { failure });
        }
        let max_stderr = self.limits.ssh().max_stderr_bytes();
        if over(&self.stderr, max_stderr) {
            return Err(ControlEndReason::StderrOverBound {
                max_bytes: max_stderr,
            });
        }
        if let Some(end) = self.stdout_end {
            return Err(match end {
                StdoutEnd::EndOfStream => ControlEndReason::EndOfStream,
                StdoutEnd::Truncated => ControlEndReason::Truncated,
                StdoutEnd::OutOfBounds { declared } => ControlEndReason::FrameOutOfBounds {
                    declared: u64::from(declared),
                    max_bytes: u64::from(MAX_CONTROL_FRAME_BYTES),
                },
                StdoutEnd::ReadFailed => ControlEndReason::PortFailed {
                    failure: PortFailure::ReadFailed,
                },
            });
        }
        if self.write_failed.is_some() {
            return Err(self.write_end());
        }
        if self.exited.is_none() {
            match self.child.try_wait() {
                Ok(Some(status)) => self.exited = Some((status, now)),
                Ok(None) => {}
                Err(_) => {
                    return Err(ControlEndReason::PortFailed {
                        failure: PortFailure::WaitFailed,
                    })
                }
            }
        }
        if let Some((_, seen)) = self.exited {
            // Frames still in the pipe are read for a bounded time after the exit.
            if now >= seen.checked_add(OUTPUT_DRAIN_WAIT).unwrap_or(seen) {
                return Err(ControlEndReason::ClientExited);
            }
        }
        let silent_for = now.saturating_duration_since(self.last_heard);
        if silent_for > self.limits.max_silence() {
            return Err(ControlEndReason::Silent {
                silent_for_ms: millis(silent_for),
            });
        }
        let max_silence = self.limits.max_silence();
        Ok(self
            .last_heard
            .checked_add(max_silence)
            .and_then(|deadline| deadline.checked_add(POLL))
            .unwrap_or(now))
    }

    /// Takes the reports of the pipe threads, waiting at most `within` for the first.
    fn pump(&mut self, within: Duration) {
        match self.events.recv_timeout(within) {
            Ok(event) => self.take(event),
            Err(RecvTimeoutError::Timeout) => return,
            // Every thread is done; only the client's end and the clock are left.
            Err(RecvTimeoutError::Disconnected) => {
                thread::sleep(within);
                return;
            }
        }
        loop {
            match self.events.try_recv() {
                Ok(event) => self.take(event),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
            }
        }
    }

    fn take(&mut self, event: Event) {
        match event {
            Event::Frame(bytes) => {
                self.last_heard = Instant::now();
                self.frames.push_back(bytes);
            }
            Event::StdoutEnded(end) => self.stdout_end = self.stdout_end.or(Some(end)),
            Event::Stderr(bytes) => self.stderr.extend(bytes),
            Event::StderrEnded { failed } => {
                self.stderr_open = false;
                if failed {
                    self.fault = self.fault.or(Some(PortFailure::ReadFailed));
                }
            }
            Event::Written => self.pending_writes = self.pending_writes.saturating_sub(1),
            Event::WriteFailed { broken_pipe } => {
                self.write_failed = self.write_failed.or(Some(broken_pipe));
            }
        }
    }

    /// Ends the channel for `reason`: closes stdin, gives a client that may be ending by
    /// itself [`OUTPUT_DRAIN_WAIT`] to exit, kills it otherwise, reaps it within
    /// [`REAP_WAIT`] and classifies what it reported.
    pub(super) fn close(mut self, reason: &ControlEndReason) -> ChannelClosed {
        let started = Instant::now();
        if reason.may_end_by_itself() {
            drop(self.outbound.take());
            let until = started.checked_add(OUTPUT_DRAIN_WAIT).unwrap_or(started);
            while self.exited.is_none() && Instant::now() < until {
                if let Ok(Some(status)) = self.child.try_wait() {
                    self.exited = Some((status, Instant::now()));
                    break;
                }
                self.pump(POLL);
            }
        }
        if self.exited.is_none() {
            if let Ok(Some(status)) = self.child.try_wait() {
                self.exited = Some((status, Instant::now()));
            }
        }
        let termination = match (self.exited, reason) {
            (Some((status, _)), _) => exit_termination(status),
            (None, ControlEndReason::Silent { .. }) => SshTermination::DeadlineReached,
            (None, _) => SshTermination::NoExitStatus,
        };
        // An error means the client has already ended, or cannot be killed; either way
        // the wait below is bounded.
        let _ = self.child.kill();
        drop(self.outbound.take());
        let until = Instant::now()
            .checked_add(REAP_WAIT)
            .unwrap_or_else(Instant::now);
        loop {
            let client_done = !matches!(self.child.try_wait(), Ok(None));
            if client_done && !self.stderr_open {
                break;
            }
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            self.pump(POLL.min(remaining));
        }
        let output = SshOutput {
            termination,
            stdout: Vec::new(),
            stderr: std::mem::take(&mut self.stderr),
        };
        let outcome = classify(&self.invocation, &output);
        ChannelClosed { output, outcome }
    }
}
