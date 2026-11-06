//! A QMP client for the QEMU backend's [`QemuMonitor`] port (M02;
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W16 row, line 2615; VM-W19 row,
//! line 2618; VM-W22 row, line 2621: record the actual accelerator, not the requested
//! flag; §7.3 lines 2378–2386; VM-CP-01, line 3151; VM-CP-03, line 3153).
//!
//! [`QmpSession`] speaks QMP over any `Read + Write`, so tests drive it with recorded
//! transcripts and production with the [`UnixStream`] of `socket.rs`:
//!
//! - it reads QEMU's greeting and negotiates no capability (`qmp_capabilities` with no
//!   arguments), then answers [`QmpSession::query_status`] (`query-status`, as the
//!   backend's [`RunState`]), [`QmpSession::query_accelerator`] (`query-accelerators`:
//!   `enabled`, the accelerator QEMU runs on, as the backend's [`Accelerator`]; a missing
//!   value, one QEMU does not list as present, or a name this backend cannot judge is a
//!   typed failure, never a guess) and [`QmpSession::quit`];
//! - a message is one line, at most [`MAX_QMP_LINE_BYTES`] with its terminator; a longer
//!   line is refused, not read on;
//! - every message is strict JSON of the shape QMP specifies: an object (never an array
//!   read as one), with unknown and duplicate members refused and event names checked;
//! - every command carries an `id`, and only a reply echoing it answers the command; a
//!   command is sent only once the previous one has its reply, and after any failure the
//!   session sends nothing more ([`QmpError::Unusable`]);
//! - asynchronous events are skipped and counted, at most [`MAX_QMP_EVENTS_PER_REPLY`]
//!   while waiting for one reply, and one exchange is bounded in time as a whole
//!   ([`DEFAULT_QMP_EXCHANGE_BUDGET`]) as well as per read by the socket's timeout, so a
//!   QEMU trickling bytes cannot hold the backend;
//! - an error reply is a typed failure with QEMU's class and description.
//!
//! QMP is the hypervisor process reporting on itself, and a guest that took over QEMU
//! controls what it says. So nothing QEMU sends reaches a refusal unbounded: its text is
//! cut to [`MAX_QMP_TEXT_BYTES`] and shown escaped.
//!
//! [`QmpMonitor`] implements [`QemuMonitor`]: each call connects through a [`QmpConnect`]
//! (production: [`UnixSocketConnect`] on the socket the profile names), opens a session,
//! runs its one command and closes. QEMU's QMP socket serves one client at a time and
//! listens again once it closes. Socket failures are [`MonitorFailure::Unreachable`],
//! everything QEMU said that was not the expected answer [`MonitorFailure::Protocol`].

use std::fmt;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Serialize};

use super::socket::{self, SocketError, SocketTimeouts, UnixStream};
use crate::foundation::evidence::HypervisorKind;
use crate::sandbox::backend::{Accelerator, Emulator};
use crate::sandbox::qemu::{HostPath, MonitorFailure, QemuMonitor, RunState};

/// Longest QMP message line accepted, terminator included.
pub const MAX_QMP_LINE_BYTES: usize = 64 * 1024;
/// Most asynchronous events skipped while waiting for one reply.
pub const MAX_QMP_EVENTS_PER_REPLY: usize = 128;
/// How long one exchange (the greeting, or one command and its reply) may take in all.
pub const DEFAULT_QMP_EXCHANGE_BUDGET: Duration = Duration::from_secs(10);
/// Most bytes of QEMU's own text (an error description, a name) kept in a failure.
pub const MAX_QMP_TEXT_BYTES: usize = 256;
/// Longest run state name accepted from `query-status`.
pub const MAX_RUN_STATE_BYTES: usize = 32;
/// Longest event name accepted.
pub const MAX_EVENT_NAME_BYTES: usize = 64;

/// The members QMP gives array values here: the greeting's `capabilities` and
/// `query-accelerators`' `present`. Their items are strings.
const ARRAY_MEMBERS: [&str; 2] = ["capabilities", "present"];

/// How many bytes one read asks for.
const READ_CHUNK_BYTES: usize = 4096;

/// The commands this client sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QmpCommand {
    Capabilities,
    QueryStatus,
    QueryAccelerators,
    Quit,
}

impl QmpCommand {
    /// The command's QMP name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Capabilities => "qmp_capabilities",
            Self::QueryStatus => "query-status",
            Self::QueryAccelerators => "query-accelerators",
            Self::Quit => "quit",
        }
    }
}

impl fmt::Display for QmpCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What the client was waiting for when it failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum QmpStep {
    Greeting,
    Reply { command: QmpCommand },
}

impl fmt::Display for QmpStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Greeting => f.write_str("QEMU's greeting"),
            Self::Reply { command } => write!(f, "the reply to {command}"),
        }
    }
}

/// The QEMU version a greeting announced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QemuVersion {
    pub major: u64,
    pub minor: u64,
    pub micro: u64,
}

impl fmt::Display for QemuVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.micro)
    }
}

/// Why QMP could not be used. Each variant says whether the monitor could not be
/// reached ([`QmpError::is_unreachable`]) or answered other than QMP specifies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum QmpError {
    /// The socket could not be connected.
    Connect { error: SocketError },
    /// A read or write did not complete in time, or the exchange exceeded its budget.
    TimedOut { step: QmpStep },
    /// A read or write failed.
    Io { step: QmpStep, detail: String },
    /// QEMU closed the connection before the message ended.
    Closed { step: QmpStep, partial_line: bool },
    /// A line was longer than [`MAX_QMP_LINE_BYTES`].
    LineTooLong { step: QmpStep, max_bytes: usize },
    /// A line was not one strict QMP message.
    Malformed { step: QmpStep, detail: String },
    /// A reply echoed another id, or none, than the command's.
    ReplyIdMismatch {
        command: QmpCommand,
        expected: u64,
        found: Option<u64>,
    },
    /// More than [`MAX_QMP_EVENTS_PER_REPLY`] events came before the reply.
    TooManyEvents { command: QmpCommand, max: usize },
    /// QEMU answered the command with an error.
    ErrorReply {
        command: QmpCommand,
        class: String,
        description: String,
    },
    /// The reply is QMP, but not the answer the command has.
    UnexpectedReply { command: QmpCommand, detail: String },
    /// `query-accelerators` named no enabled accelerator.
    AcceleratorMissing,
    /// `query-accelerators` named an enabled accelerator it does not list as present.
    AcceleratorNotPresent { name: String },
    /// `query-accelerators` named an accelerator this backend cannot judge.
    UnknownAccelerator { name: String },
    /// An earlier exchange failed or the session quit; nothing more is sent.
    Unusable,
}

impl QmpError {
    /// Whether the monitor could not be reached, rather than answering wrongly.
    pub fn is_unreachable(&self) -> bool {
        matches!(
            self,
            Self::Connect { .. } | Self::TimedOut { .. } | Self::Io { .. } | Self::Closed { .. }
        )
    }

    fn io(step: QmpStep, error: &io::Error) -> Self {
        match SocketError::from_io(error) {
            Some(SocketError::TimedOut { .. } | SocketError::UnusableAfterTimeout) => {
                Self::TimedOut { step }
            }
            _ if error.kind() == io::ErrorKind::TimedOut => Self::TimedOut { step },
            _ => Self::Io {
                step,
                detail: error.to_string(),
            },
        }
    }
}

impl fmt::Display for QmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect { error } => write!(f, "the QMP socket could not be connected: {error}"),
            Self::TimedOut { step } => write!(f, "{step} did not arrive in time"),
            Self::Io { step, detail } => write!(f, "reading {step} failed: {detail}"),
            Self::Closed { step, partial_line } => write!(
                f,
                "QEMU closed the connection before {step}{}",
                if *partial_line { " ended" } else { "" }
            ),
            Self::LineTooLong { step, max_bytes } => {
                write!(f, "{step} is a line longer than {max_bytes} bytes")
            }
            Self::Malformed { step, detail } => {
                write!(f, "{step} is not a strict QMP message: {detail}")
            }
            Self::ReplyIdMismatch {
                command,
                expected,
                found,
            } => match found {
                Some(found) => write!(f, "the reply to {command} {expected} echoes id {found}"),
                None => write!(f, "the reply to {command} {expected} echoes no id"),
            },
            Self::TooManyEvents { command, max } => {
                write!(
                    f,
                    "more than {max} events came before the reply to {command}"
                )
            }
            Self::ErrorReply {
                command,
                class,
                description,
            } => write!(f, "QEMU refused {command}: {class:?}: {description:?}"),
            Self::UnexpectedReply { command, detail } => {
                write!(f, "the reply to {command} is not its answer: {detail}")
            }
            Self::AcceleratorMissing => {
                f.write_str("query-accelerators named no enabled accelerator")
            }
            Self::AcceleratorNotPresent { name } => write!(
                f,
                "query-accelerators named {name:?} enabled but not present"
            ),
            Self::UnknownAccelerator { name } => write!(
                f,
                "query-accelerators named {name:?}, which is no accelerator this backend judges"
            ),
            Self::Unusable => {
                f.write_str("the QMP session failed or quit earlier, so no further command is sent")
            }
        }
    }
}

impl std::error::Error for QmpError {}

impl From<QmpError> for MonitorFailure {
    fn from(error: QmpError) -> Self {
        if error.is_unreachable() {
            Self::Unreachable {
                detail: error.to_string(),
            }
        } else {
            Self::Protocol {
                detail: error.to_string(),
            }
        }
    }
}

/// Why `line` is not a JSON object of QMP's shape, if it is not. serde reads a struct from
/// a JSON array as well as from an object, so the structure is checked on the parsed
/// value first: an object, with arrays of plain values only under [`ARRAY_MEMBERS`]. An
/// event's `data` is not looked into.
fn shape_problem(line: &[u8]) -> Option<String> {
    let value: serde_json::Value = match serde_json::from_slice(line) {
        Ok(value) => value,
        Err(error) => return Some(error.to_string()),
    };
    let serde_json::Value::Object(members) = &value else {
        return Some("the message is not a JSON object".to_owned());
    };
    let shaped = members
        .iter()
        .all(|(key, member)| key == "data" || member_shaped(key, member));
    (!shaped).then(|| "the message has an array where QMP has none".to_owned())
}

fn member_shaped(key: &str, value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(members) => members
            .iter()
            .all(|(key, member)| member_shaped(key, member)),
        serde_json::Value::Array(items) => {
            ARRAY_MEMBERS.contains(&key)
                && items
                    .iter()
                    .all(|item| !item.is_array() && !item.is_object())
        }
        _ => true,
    }
}

/// Whether `name` is a QAPI event name: uppercase letters, digits and underscores.
fn event_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_EVENT_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// At most [`MAX_QMP_TEXT_BYTES`] of QEMU's text, cut at a character boundary.
fn bounded(text: &str) -> String {
    if text.len() <= MAX_QMP_TEXT_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_QMP_TEXT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

/// The accelerator a QMP accelerator name stands for: a hardware hypervisor QEMU can run
/// on (WHPX, KVM, HVF), or TCG. Every other name (`qtest`, `xen`, `nvmm`, anything new)
/// is not one this backend can judge.
pub fn accelerator_from_qmp(name: &str) -> Option<Accelerator> {
    if name == Emulator::Tcg.tag() {
        return Some(Accelerator::Emulation {
            emulator: Emulator::Tcg,
        });
    }
    [
        HypervisorKind::Whpx,
        HypervisorKind::Kvm,
        HypervisorKind::Hvf,
    ]
    .into_iter()
    .find(|hypervisor| hypervisor.tag() == name)
    .map(|hypervisor| Accelerator::Hardware { hypervisor })
}

/// The QMP name of an accelerator, as the [`QemuMonitor`] port reports it.
pub fn accelerator_name(accelerator: Accelerator) -> &'static str {
    match accelerator {
        Accelerator::Hardware { hypervisor } => hypervisor.tag(),
        Accelerator::Emulation { emulator } => emulator.tag(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GreetingMessage {
    #[serde(rename = "QMP")]
    qmp: GreetingBody,
}

/// The greeting's body. The capabilities QEMU offers are read and not enabled.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GreetingBody {
    version: GreetingVersion,
    #[serde(rename = "capabilities")]
    _capabilities: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GreetingVersion {
    qemu: QemuVersion,
    #[serde(rename = "package")]
    _package: String,
}

/// One message after the greeting: a reply carrying `T`, an error reply or an event.
#[derive(Deserialize)]
#[serde(untagged)]
enum Incoming<T> {
    Return(ReturnMessage<T>),
    Error(ErrorMessage),
    Event(EventMessage),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReturnMessage<T> {
    #[serde(rename = "return")]
    value: T,
    id: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorMessage {
    error: ErrorBody,
    id: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorBody {
    class: String,
    desc: String,
}

/// An asynchronous event: checked for its shape and name, then skipped.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventMessage {
    event: String,
    #[serde(rename = "data", default)]
    _data: Option<IgnoredAny>,
    #[serde(rename = "timestamp")]
    _timestamp: Timestamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Timestamp {
    #[serde(rename = "seconds")]
    _seconds: i64,
    #[serde(rename = "microseconds")]
    _microseconds: i64,
}

/// The empty object `qmp_capabilities` and `quit` return.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

/// `query-status`'s answer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusInfo {
    running: bool,
    status: String,
}

/// `query-accelerators`' answer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceleratorInfo {
    enabled: Option<String>,
    present: Vec<String>,
}

/// One QMP connection after the greeting and capability negotiation (see the module
/// notes).
pub struct QmpSession<S> {
    stream: S,
    pending: Vec<u8>,
    next_id: u64,
    events_skipped: u64,
    version: QemuVersion,
    budget: Duration,
    usable: bool,
}

impl<S> fmt::Debug for QmpSession<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QmpSession")
            .field("version", &self.version)
            .field("next_id", &self.next_id)
            .field("events_skipped", &self.events_skipped)
            .field("usable", &self.usable)
            .finish_non_exhaustive()
    }
}

/// Whether QMP answers on `stream`: QEMU's greeting read strictly and the capability
/// negotiation answered, each exchange within `budget`. A host port waiting for a start
/// asks this rather than whether a connection was accepted: QEMU listens on its QMP socket
/// before it sets up the accelerator and the machine, and the kernel queues a connection
/// then, but QEMU answers one only from its main loop, once both are up. The connection
/// is closed afterwards.
pub fn answers<S: Read + Write>(stream: S, budget: Duration) -> bool {
    QmpSession::open_within(stream, budget).is_ok()
}

impl<S: Read + Write> QmpSession<S> {
    /// Reads the greeting and negotiates no capability, with the default exchange budget.
    pub fn open(stream: S) -> Result<Self, QmpError> {
        Self::open_within(stream, DEFAULT_QMP_EXCHANGE_BUDGET)
    }

    /// As [`open`](Self::open), with `budget` for each exchange.
    pub fn open_within(stream: S, budget: Duration) -> Result<Self, QmpError> {
        let mut session = Self {
            stream,
            pending: Vec::new(),
            next_id: 1,
            events_skipped: 0,
            version: QemuVersion {
                major: 0,
                minor: 0,
                micro: 0,
            },
            budget,
            usable: false,
        };
        let started = Instant::now();
        let line = session.read_line(QmpStep::Greeting, started)?;
        if let Some(detail) = shape_problem(&line) {
            return Err(QmpError::Malformed {
                step: QmpStep::Greeting,
                detail,
            });
        }
        let greeting: GreetingMessage =
            serde_json::from_slice(&line).map_err(|error| QmpError::Malformed {
                step: QmpStep::Greeting,
                detail: error.to_string(),
            })?;
        session.version = greeting.qmp.version.qemu;
        session.usable = true;
        let Empty {} = session.execute(QmpCommand::Capabilities)?;
        Ok(session)
    }

    /// The QEMU version the greeting announced.
    pub fn version(&self) -> QemuVersion {
        self.version
    }

    /// How many asynchronous events this session skipped.
    pub fn events_skipped(&self) -> u64 {
        self.events_skipped
    }

    /// QEMU's run state (`query-status`): running, or QEMU's own word for any other
    /// state. A reply whose `running` flag contradicts its state is a failure.
    pub fn query_status(&mut self) -> Result<RunState, QmpError> {
        let command = QmpCommand::QueryStatus;
        let StatusInfo { running, status } = self.execute(command)?;
        let valid = !status.is_empty()
            && status.len() <= MAX_RUN_STATE_BYTES
            && status
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-');
        if !valid {
            return Err(self.fail(QmpError::UnexpectedReply {
                command,
                detail: format!("{:?} is not a run state name", bounded(&status)),
            }));
        }
        match (running, status == "running") {
            (true, true) => Ok(RunState::Running),
            (false, false) => Ok(RunState::NotRunning { status }),
            _ => Err(self.fail(QmpError::UnexpectedReply {
                command,
                detail: format!("running is {running} but the state is {status:?}"),
            })),
        }
    }

    /// The accelerator QEMU runs on (`query-accelerators`' `enabled`), which must be one
    /// it lists as present and one this backend can judge.
    pub fn query_accelerator(&mut self) -> Result<Accelerator, QmpError> {
        let AcceleratorInfo { enabled, present } = self.execute(QmpCommand::QueryAccelerators)?;
        let Some(name) = enabled else {
            return Err(self.fail(QmpError::AcceleratorMissing));
        };
        if !present.contains(&name) {
            return Err(self.fail(QmpError::AcceleratorNotPresent {
                name: bounded(&name),
            }));
        }
        match accelerator_from_qmp(&name) {
            Some(accelerator) => Ok(accelerator),
            None => Err(self.fail(QmpError::UnknownAccelerator {
                name: bounded(&name),
            })),
        }
    }

    /// Asks QEMU to quit and reads its acknowledgement. Only the host process port's
    /// proof shows the process ended. The session sends nothing afterwards.
    pub fn quit(&mut self) -> Result<(), QmpError> {
        let Empty {} = self.execute(QmpCommand::Quit)?;
        self.usable = false;
        Ok(())
    }

    /// The stream, for a caller that ends it.
    pub fn into_inner(self) -> S {
        self.stream
    }

    fn fail(&mut self, error: QmpError) -> QmpError {
        self.usable = false;
        error
    }

    /// Sends `command` with a fresh id and reads until its reply, skipping events.
    fn execute<T: DeserializeOwned>(&mut self, command: QmpCommand) -> Result<T, QmpError> {
        if !self.usable {
            return Err(QmpError::Unusable);
        }
        // Set again only once the reply was read.
        self.usable = false;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let step = QmpStep::Reply { command };
        let started = Instant::now();
        let line = format!("{{\"execute\":\"{}\",\"id\":{id}}}\n", command.name());
        self.stream
            .write_all(line.as_bytes())
            .and_then(|()| self.stream.flush())
            .map_err(|error| QmpError::io(step, &error))?;
        let mut events = 0usize;
        loop {
            let line = self.read_line(step, started)?;
            if let Some(detail) = shape_problem(&line) {
                return Err(QmpError::Malformed { step, detail });
            }
            match serde_json::from_slice::<Incoming<T>>(&line) {
                Ok(Incoming::Event(event)) => {
                    if !event_name_valid(&event.event) {
                        return Err(QmpError::Malformed {
                            step,
                            detail: format!("{:?} is not an event name", bounded(&event.event)),
                        });
                    }
                    events += 1;
                    self.events_skipped = self.events_skipped.saturating_add(1);
                    if events > MAX_QMP_EVENTS_PER_REPLY {
                        return Err(QmpError::TooManyEvents {
                            command,
                            max: MAX_QMP_EVENTS_PER_REPLY,
                        });
                    }
                }
                Ok(Incoming::Return(reply)) => {
                    check_id(command, id, reply.id)?;
                    self.usable = true;
                    return Ok(reply.value);
                }
                Ok(Incoming::Error(reply)) => {
                    check_id(command, id, reply.id)?;
                    return Err(QmpError::ErrorReply {
                        command,
                        class: bounded(&reply.error.class),
                        description: bounded(&reply.error.desc),
                    });
                }
                Err(_) => return Err(Self::not_the_answer(command, id, &line)),
            }
        }
    }

    /// Why a line that is not the expected message was refused: a reply of another shape
    /// to this command, or no strict QMP message at all.
    fn not_the_answer(command: QmpCommand, id: u64, line: &[u8]) -> QmpError {
        match serde_json::from_slice::<Incoming<IgnoredAny>>(line) {
            Ok(Incoming::Return(reply)) => match check_id(command, id, reply.id) {
                Ok(()) => QmpError::UnexpectedReply {
                    command,
                    detail: "the returned value has another shape".to_owned(),
                },
                Err(error) => error,
            },
            Ok(_) => QmpError::Malformed {
                step: QmpStep::Reply { command },
                detail: "the message has an unexpected shape".to_owned(),
            },
            Err(error) => QmpError::Malformed {
                step: QmpStep::Reply { command },
                detail: error.to_string(),
            },
        }
    }

    /// The next line without its terminator (`\n`, or `\r\n` as QEMU writes it).
    fn read_line(&mut self, step: QmpStep, started: Instant) -> Result<Vec<u8>, QmpError> {
        // Bytes of `pending` already known to hold no line end.
        let mut scanned = 0;
        loop {
            let found = self.pending[scanned..]
                .iter()
                .position(|byte| *byte == b'\n');
            if let Some(index) = found.map(|offset| scanned + offset) {
                if index >= MAX_QMP_LINE_BYTES {
                    return Err(QmpError::LineTooLong {
                        step,
                        max_bytes: MAX_QMP_LINE_BYTES,
                    });
                }
                let mut line: Vec<u8> = self.pending.drain(..=index).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            scanned = self.pending.len();
            if self.pending.len() >= MAX_QMP_LINE_BYTES {
                return Err(QmpError::LineTooLong {
                    step,
                    max_bytes: MAX_QMP_LINE_BYTES,
                });
            }
            if started.elapsed() > self.budget {
                return Err(QmpError::TimedOut { step });
            }
            let mut chunk = [0u8; READ_CHUNK_BYTES];
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(QmpError::Closed {
                        step,
                        partial_line: !self.pending.is_empty(),
                    })
                }
                Ok(read) => self
                    .pending
                    .extend_from_slice(&chunk[..read.min(chunk.len())]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(QmpError::io(step, &error)),
            }
        }
    }
}

fn check_id(command: QmpCommand, expected: u64, found: Option<u64>) -> Result<(), QmpError> {
    if found == Some(expected) {
        Ok(())
    } else {
        Err(QmpError::ReplyIdMismatch {
            command,
            expected,
            found,
        })
    }
}

/// How the monitor reaches QMP on a socket path.
pub trait QmpConnect {
    type Stream: Read + Write;

    fn connect(&self, socket: &HostPath) -> Result<Self::Stream, QmpError>;
}

/// Connects to the AF_UNIX socket at the path the profile names, with these timeouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnixSocketConnect {
    pub timeouts: SocketTimeouts,
}

impl QmpConnect for UnixSocketConnect {
    type Stream = UnixStream;

    fn connect(&self, socket: &HostPath) -> Result<UnixStream, QmpError> {
        socket::connect(Path::new(socket.as_str()), self.timeouts)
            .map_err(|error| QmpError::Connect { error })
    }
}

/// The [`QemuMonitor`] port over QMP: one session per call (see the module notes).
#[derive(Debug)]
pub struct QmpMonitor<C> {
    connect: C,
    budget: Duration,
    events_skipped: AtomicU64,
}

impl<C: QmpConnect> QmpMonitor<C> {
    /// A monitor whose sessions have [`DEFAULT_QMP_EXCHANGE_BUDGET`] for each exchange.
    pub fn new(connect: C) -> Self {
        Self::with_budget(connect, DEFAULT_QMP_EXCHANGE_BUDGET)
    }

    /// A monitor whose sessions have `budget` for each exchange.
    pub fn with_budget(connect: C, budget: Duration) -> Self {
        Self {
            connect,
            budget,
            events_skipped: AtomicU64::new(0),
        }
    }

    /// How many asynchronous events this monitor's sessions skipped.
    pub fn events_skipped(&self) -> u64 {
        self.events_skipped.load(Ordering::Relaxed)
    }

    /// Opens a session on `socket`, runs `command` in it and closes it, counting the
    /// events it skipped.
    fn with_session<T>(
        &self,
        socket: &HostPath,
        command: impl FnOnce(&mut QmpSession<C::Stream>) -> Result<T, QmpError>,
    ) -> Result<T, QmpError> {
        let stream = self.connect.connect(socket)?;
        let mut session = QmpSession::open_within(stream, self.budget)?;
        let result = command(&mut session);
        self.events_skipped
            .fetch_add(session.events_skipped(), Ordering::Relaxed);
        result
    }

    /// The accelerator QEMU runs on, typed.
    pub fn query_accelerator(&self, socket: &HostPath) -> Result<Accelerator, QmpError> {
        self.with_session(socket, QmpSession::query_accelerator)
    }
}

impl<C: QmpConnect> QemuMonitor for QmpMonitor<C> {
    /// The QMP name of the accelerator QEMU reports it runs on; only names that map to a
    /// backend accelerator are returned.
    fn accelerator(&self, socket: &HostPath) -> Result<String, MonitorFailure> {
        let accelerator = self.query_accelerator(socket)?;
        Ok(accelerator_name(accelerator).to_owned())
    }

    fn status(&self, socket: &HostPath) -> Result<RunState, MonitorFailure> {
        Ok(self.with_session(socket, QmpSession::query_status)?)
    }

    fn quit(&mut self, socket: &HostPath) -> Result<(), MonitorFailure> {
        Ok(self.with_session(socket, QmpSession::quit)?)
    }
}
