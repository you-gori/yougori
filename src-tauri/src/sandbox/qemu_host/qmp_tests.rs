//! QMP client tests over transcripts: QEMU 11.1.0's greeting and its replies to
//! `qmp_capabilities`, `query-status` and `query-accelerators` exactly as recorded on this
//! host by `qemu_run_tests.rs` (2026-10-29), with events, error replies, oversize,
//! malformed and mismatched lines, and slow or failing streams added.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::Mutex;
use std::time::Duration;

use super::qmp::*;
use crate::foundation::evidence::HypervisorKind;
use crate::sandbox::backend::{Accelerator, Emulator};
use crate::sandbox::qemu::{HostPath, MonitorFailure, PathStyle, QemuMonitor, RunState};

/// QEMU 11.1.0's greeting on the QMP socket, as recorded.
const GREETING: &str = r#"{"QMP": {"version": {"qemu": {"micro": 0, "minor": 1, "major": 11}, "package": ""}, "capabilities": ["oob"]}}"#;
const CAPABILITIES_OK: &str = r#"{"return": {}, "id": 1}"#;
const RESUME_EVENT: &str =
    r#"{"timestamp": {"seconds": 1761772150, "microseconds": 123456}, "event": "RESUME"}"#;
const SHUTDOWN_EVENT: &str = r#"{"timestamp": {"seconds": 1761772151, "microseconds": 1}, "event": "SHUTDOWN", "data": {"guest": false, "reason": "host-qmp-quit"}}"#;

/// A scripted QEMU side: what it sends, in reads of at most `chunk` bytes, then an end
/// of stream or an error; what the client wrote is kept.
struct Transcript {
    input: Vec<u8>,
    position: usize,
    chunk: usize,
    end: Option<io::ErrorKind>,
    delay: Duration,
    written: Vec<u8>,
}

impl Transcript {
    /// QEMU's lines, each ended with `\r\n` as QEMU writes them.
    fn lines(lines: &[&str]) -> Self {
        let mut input = Vec::new();
        for line in lines {
            input.extend_from_slice(line.as_bytes());
            input.extend_from_slice(b"\r\n");
        }
        Self::bytes(input)
    }

    fn bytes(input: Vec<u8>) -> Self {
        Self {
            input,
            position: 0,
            chunk: 7,
            end: None,
            delay: Duration::ZERO,
            written: Vec::new(),
        }
    }

    fn ending_with(mut self, kind: io::ErrorKind) -> Self {
        self.end = Some(kind);
        self
    }

    fn written(&self) -> String {
        String::from_utf8(self.written.clone()).unwrap()
    }
}

impl Read for Transcript {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        if self.position == self.input.len() {
            return match self.end {
                Some(kind) => Err(io::Error::new(kind, "scripted")),
                None => Ok(0),
            };
        }
        let count = buffer
            .len()
            .min(self.chunk)
            .min(self.input.len() - self.position);
        buffer[..count].copy_from_slice(&self.input[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

impl Write for Transcript {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A session opened on `lines` after the greeting and the capabilities reply.
fn opened(lines: &[&str]) -> QmpSession<Transcript> {
    let mut all = vec![GREETING, CAPABILITIES_OK];
    all.extend_from_slice(lines);
    QmpSession::open(Transcript::lines(&all)).unwrap()
}

fn status_reply(id: u64, status: &str, running: bool) -> String {
    format!(r#"{{"return": {{"status": "{status}", "running": {running}}}, "id": {id}}}"#)
}

fn accelerators_reply(id: u64, enabled: &str, present: &[&str]) -> String {
    let present: Vec<String> = present.iter().map(|name| format!("\"{name}\"")).collect();
    format!(
        r#"{{"return": {{"enabled": "{enabled}", "present": [{}]}}, "id": {id}}}"#,
        present.join(", ")
    )
}

#[test]
fn a_session_greets_negotiates_queries_and_quits() {
    let status = status_reply(2, "prelaunch", false);
    let accelerators = accelerators_reply(3, "whpx", &["qtest", "tcg", "whpx"]);
    let mut session = opened(&[&status, &accelerators, r#"{"return": {}, "id": 4}"#]);
    assert_eq!(
        session.version(),
        QemuVersion {
            major: 11,
            minor: 1,
            micro: 0
        }
    );
    assert_eq!(
        session.query_status().unwrap(),
        RunState::NotRunning {
            status: "prelaunch".into()
        }
    );
    assert_eq!(
        session.query_accelerator().unwrap(),
        Accelerator::Hardware {
            hypervisor: HypervisorKind::Whpx
        }
    );
    session.quit().unwrap();
    assert_eq!(session.query_status(), Err(QmpError::Unusable));
    assert_eq!(session.events_skipped(), 0);
    assert_eq!(
        session.into_inner().written(),
        "{\"execute\":\"qmp_capabilities\",\"id\":1}\n\
         {\"execute\":\"query-status\",\"id\":2}\n\
         {\"execute\":\"query-accelerators\",\"id\":3}\n\
         {\"execute\":\"quit\",\"id\":4}\n"
    );
}

#[test]
fn run_states_map_to_the_backend_run_state() {
    for (status, running, expected) in [
        ("running", true, RunState::Running),
        (
            "paused",
            false,
            RunState::NotRunning {
                status: "paused".into(),
            },
        ),
        (
            "internal-error",
            false,
            RunState::NotRunning {
                status: "internal-error".into(),
            },
        ),
    ] {
        let reply = status_reply(2, status, running);
        assert_eq!(opened(&[&reply]).query_status().unwrap(), expected);
    }
    for (reply, detail) in [
        (status_reply(2, "paused", true), "running is true"),
        (status_reply(2, "running", false), "running is false"),
        (status_reply(2, "Paused!", false), "not a run state name"),
        (status_reply(2, "", false), "not a run state name"),
        (
            status_reply(2, &"a".repeat(MAX_RUN_STATE_BYTES + 1), false),
            "not a run state name",
        ),
        (
            r#"{"return": {"status": "running", "running": true, "singlestep": false}, "id": 2}"#
                .to_owned(),
            "another shape",
        ),
        (
            r#"{"return": {"status": "running"}, "id": 2}"#.to_owned(),
            "another shape",
        ),
    ] {
        let mut session = opened(&[&reply]);
        match session.query_status() {
            Err(QmpError::UnexpectedReply {
                command,
                detail: found,
            }) => {
                assert_eq!(command, QmpCommand::QueryStatus);
                assert!(found.contains(detail), "{found}");
            }
            other => panic!("{reply}: {other:?}"),
        }
        assert_eq!(session.query_status(), Err(QmpError::Unusable));
    }
}

#[test]
fn a_struct_given_as_an_array_is_refused() {
    let array = r#"{"return": [true, "running"], "id": 2}"#;
    assert!(matches!(
        opened(&[array]).query_status(),
        Err(QmpError::Malformed { .. })
    ));
    let nested = r#"{"return": {"enabled": "whpx", "present": [["whpx"]]}, "id": 2}"#;
    assert!(matches!(
        opened(&[nested]).query_accelerator(),
        Err(QmpError::Malformed { .. })
    ));
    let greeting = r#"{"QMP": {"version": [[11, 1, 0], ""], "capabilities": []}}"#;
    assert!(matches!(
        QmpSession::open(Transcript::lines(&[greeting])),
        Err(QmpError::Malformed {
            step: QmpStep::Greeting,
            ..
        })
    ));
}

#[test]
fn the_accelerator_is_what_qemu_runs_on_and_never_guessed() {
    let tcg = accelerators_reply(2, "tcg", &["qtest", "tcg"]);
    assert_eq!(
        opened(&[&tcg]).query_accelerator().unwrap(),
        Accelerator::Emulation {
            emulator: Emulator::Tcg
        }
    );
    let missing = r#"{"return": {"present": ["tcg", "whpx"]}, "id": 2}"#;
    assert_eq!(
        opened(&[missing]).query_accelerator(),
        Err(QmpError::AcceleratorMissing)
    );
    let absent = accelerators_reply(2, "kvm", &["tcg", "whpx"]);
    assert_eq!(
        opened(&[&absent]).query_accelerator(),
        Err(QmpError::AcceleratorNotPresent { name: "kvm".into() })
    );
    for unknown in ["qtest", "xen", "nvmm", "WHPX"] {
        let reply = accelerators_reply(2, unknown, &[unknown]);
        assert_eq!(
            opened(&[&reply]).query_accelerator(),
            Err(QmpError::UnknownAccelerator {
                name: unknown.into()
            })
        );
    }
    let extra = r#"{"return": {"enabled": "whpx", "present": ["whpx"], "x": 1}, "id": 2}"#;
    assert!(matches!(
        opened(&[extra]).query_accelerator(),
        Err(QmpError::UnexpectedReply { .. })
    ));
}

#[test]
fn qmp_accelerator_names_map_only_to_known_accelerators() {
    for (name, hypervisor) in [
        ("whpx", HypervisorKind::Whpx),
        ("kvm", HypervisorKind::Kvm),
        ("hvf", HypervisorKind::Hvf),
    ] {
        let accelerator = Accelerator::Hardware { hypervisor };
        assert_eq!(accelerator_from_qmp(name), Some(accelerator));
        assert_eq!(accelerator_name(accelerator), name);
    }
    assert_eq!(
        accelerator_name(Accelerator::Emulation {
            emulator: Emulator::Tcg
        }),
        "tcg"
    );
    for other in ["hcs", "vz", "qtest", "xen", "nvmm", "", "whpx "] {
        assert_eq!(accelerator_from_qmp(other), None, "{other:?}");
    }
}

#[test]
fn events_are_skipped_and_counted_up_to_a_bound() {
    let status = status_reply(2, "running", true);
    let mut session = opened(&[
        RESUME_EVENT,
        SHUTDOWN_EVENT,
        &status,
        r#"{"return": {}, "id": 3}"#,
    ]);
    assert_eq!(session.query_status().unwrap(), RunState::Running);
    assert_eq!(session.events_skipped(), 2);
    session.quit().unwrap();

    let mut lines: Vec<&str> = vec![RESUME_EVENT; MAX_QMP_EVENTS_PER_REPLY];
    lines.push(&status);
    assert_eq!(opened(&lines).query_status().unwrap(), RunState::Running);
    lines.insert(0, RESUME_EVENT);
    assert_eq!(
        opened(&lines).query_status(),
        Err(QmpError::TooManyEvents {
            command: QmpCommand::QueryStatus,
            max: MAX_QMP_EVENTS_PER_REPLY
        })
    );
}

#[test]
fn an_error_reply_is_a_typed_failure_and_ends_the_session() {
    let error = r#"{"id": 2, "error": {"class": "CommandNotFound", "desc": "The command query-status has not been found"}}"#;
    let mut session = opened(&[error]);
    let failure = session.query_status().unwrap_err();
    assert_eq!(
        failure,
        QmpError::ErrorReply {
            command: QmpCommand::QueryStatus,
            class: "CommandNotFound".into(),
            description: "The command query-status has not been found".into(),
        }
    );
    assert!(!failure.is_unreachable());
    assert!(matches!(
        MonitorFailure::from(failure),
        MonitorFailure::Protocol { .. }
    ));
    assert_eq!(session.query_status(), Err(QmpError::Unusable));
}

#[test]
fn qemu_text_in_a_failure_is_bounded() {
    let description = "\u{1b}[31m".to_owned() + &"x".repeat(10_000);
    let error = format!(
        r#"{{"error": {{"class": "GenericError", "desc": "{}"}}, "id": 2}}"#,
        description.replace('\u{1b}', "\\u001b")
    );
    match opened(&[&error]).query_status() {
        Err(QmpError::ErrorReply { description, .. }) => {
            assert!(
                description.len() <= MAX_QMP_TEXT_BYTES + 3,
                "{}",
                description.len()
            );
            let failure = QmpError::ErrorReply {
                command: QmpCommand::QueryStatus,
                class: "GenericError".into(),
                description,
            };
            assert!(!failure.to_string().contains('\u{1b}'));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn replies_must_echo_the_command_id() {
    for (reply, found) in [
        (status_reply(7, "running", true), Some(7)),
        (
            r#"{"return": {"status": "running", "running": true}}"#.to_owned(),
            None,
        ),
        (
            r#"{"error": {"class": "GenericError", "desc": "bad"}}"#.to_owned(),
            None,
        ),
        (r#"{"return": 5, "id": 9}"#.to_owned(), Some(9)),
    ] {
        assert_eq!(
            opened(&[&reply]).query_status(),
            Err(QmpError::ReplyIdMismatch {
                command: QmpCommand::QueryStatus,
                expected: 2,
                found
            }),
            "{reply}"
        );
    }
    let wrong_capabilities = Transcript::lines(&[GREETING, r#"{"return": {}, "id": 0}"#]);
    assert!(matches!(
        QmpSession::open(wrong_capabilities),
        Err(QmpError::ReplyIdMismatch {
            command: QmpCommand::Capabilities,
            expected: 1,
            found: Some(0)
        })
    ));
}

#[test]
fn malformed_lines_are_refused() {
    for line in [
        "not json",
        "[1, 2]",
        "{}",
        r#"{"return": {}, "id": 2, "extra": 1}"#,
        r#"{"return": {}, "return": {}, "id": 2}"#,
        r#"{"event": "RESUME"}"#,
        r#"{"event": "RESUME", "timestamp": {"seconds": 1, "microseconds": 2}, "x": 0}"#,
        r#"{"error": {"class": "GenericError"}, "id": 2}"#,
        r#"{"return": {}, "id": 2} trailing"#,
        "",
        r#"{"return": [], "id": 2}"#,
        r#"{"return": {"x": [1]}, "id": 2}"#,
        r#"{"event": "resume", "timestamp": {"seconds": 1, "microseconds": 2}}"#,
        r#"{"event": "", "timestamp": {"seconds": 1, "microseconds": 2}}"#,
        r#"{"event": "RESUME", "timestamp": [1, 2]}"#,
    ] {
        let mut session = opened(&[line]);
        match session.quit() {
            Err(QmpError::Malformed { step, .. }) => {
                assert_eq!(
                    step,
                    QmpStep::Reply {
                        command: QmpCommand::Quit
                    },
                    "{line}"
                );
            }
            other => panic!("{line:?}: {other:?}"),
        }
        assert_eq!(session.quit(), Err(QmpError::Unusable));
    }
    let mut bytes = Vec::new();
    for line in [GREETING, CAPABILITIES_OK] {
        bytes.extend_from_slice(line.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"{\"return\": {}, \"id\": \xff}\r\n");
    let mut session = QmpSession::open(Transcript::bytes(bytes)).unwrap();
    assert!(matches!(session.quit(), Err(QmpError::Malformed { .. })));
    for greeting in [
        r#"{"QMP": {"version": {"qemu": {"micro": 0, "minor": 1, "major": 11}, "package": ""}}}"#,
        r#"{"QMP": {"version": {"qemu": {"micro": 0, "minor": 1, "major": 11}, "package": ""}, "capabilities": [], "x": 1}}"#,
        r#"{"return": {}, "id": 1}"#,
        RESUME_EVENT,
    ] {
        assert!(
            matches!(
                QmpSession::open(Transcript::lines(&[greeting])),
                Err(QmpError::Malformed {
                    step: QmpStep::Greeting,
                    ..
                })
            ),
            "{greeting}"
        );
    }
}

#[test]
fn oversize_lines_are_refused_without_reading_on() {
    let long = format!(
        r#"{{"return": {{}}, "id": 2, "pad": "{}"}}"#,
        "p".repeat(MAX_QMP_LINE_BYTES)
    );
    let mut session = opened(&[&long]);
    assert_eq!(
        session.quit(),
        Err(QmpError::LineTooLong {
            step: QmpStep::Reply {
                command: QmpCommand::Quit
            },
            max_bytes: MAX_QMP_LINE_BYTES
        })
    );
    let mut endless = Vec::new();
    for line in [GREETING, CAPABILITIES_OK] {
        endless.extend_from_slice(line.as_bytes());
        endless.extend_from_slice(b"\r\n");
    }
    endless.extend(std::iter::repeat_n(b' ', 4 * MAX_QMP_LINE_BYTES));
    let mut transcript = Transcript::bytes(endless);
    transcript.chunk = 4096;
    let mut session = QmpSession::open(transcript).unwrap();
    assert!(matches!(session.quit(), Err(QmpError::LineTooLong { .. })));
    let read = session.into_inner().position;
    assert!(read < MAX_QMP_LINE_BYTES + 3 * 4096, "{read}");
    let fits = format!(
        r#"{{"return": {{"status": "running", "running": true}}, "id": 2}}{}"#,
        " ".repeat(MAX_QMP_LINE_BYTES - 64)
    );
    assert!(fits.len() + 2 <= MAX_QMP_LINE_BYTES);
    assert_eq!(opened(&[&fits]).query_status().unwrap(), RunState::Running);
}

#[test]
fn a_closed_or_failing_stream_is_unreachable() {
    assert_eq!(
        QmpSession::open(Transcript::bytes(Vec::new())).unwrap_err(),
        QmpError::Closed {
            step: QmpStep::Greeting,
            partial_line: false
        }
    );
    let partial = Transcript::bytes(GREETING.as_bytes()[..20].to_vec());
    assert_eq!(
        QmpSession::open(partial).unwrap_err(),
        QmpError::Closed {
            step: QmpStep::Greeting,
            partial_line: true
        }
    );
    let timed_out = Transcript::lines(&[GREETING]).ending_with(io::ErrorKind::TimedOut);
    let error = QmpSession::open(timed_out).unwrap_err();
    assert_eq!(
        error,
        QmpError::TimedOut {
            step: QmpStep::Reply {
                command: QmpCommand::Capabilities
            }
        }
    );
    assert!(error.is_unreachable());
    assert!(matches!(
        MonitorFailure::from(error),
        MonitorFailure::Unreachable { .. }
    ));
    let reset = Transcript::lines(&[GREETING]).ending_with(io::ErrorKind::ConnectionReset);
    assert!(matches!(QmpSession::open(reset), Err(QmpError::Io { .. })));
}

#[test]
fn an_exchange_is_bounded_in_time_as_a_whole() {
    let mut slow = Transcript::lines(&[GREETING, CAPABILITIES_OK]);
    slow.chunk = 1;
    slow.delay = Duration::from_millis(5);
    let started = std::time::Instant::now();
    assert_eq!(
        QmpSession::open_within(slow, Duration::from_millis(60)).unwrap_err(),
        QmpError::TimedOut {
            step: QmpStep::Greeting
        }
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// Hands out one scripted transcript per connection and records the socket paths.
struct ScriptedConnect {
    streams: Mutex<VecDeque<Result<Transcript, QmpError>>>,
    sockets: Mutex<Vec<String>>,
}

impl ScriptedConnect {
    fn new(streams: Vec<Result<Transcript, QmpError>>) -> Self {
        Self {
            streams: Mutex::new(streams.into()),
            sockets: Mutex::new(Vec::new()),
        }
    }
}

impl QmpConnect for &ScriptedConnect {
    type Stream = Transcript;

    fn connect(&self, socket: &HostPath) -> Result<Transcript, QmpError> {
        self.sockets
            .lock()
            .unwrap()
            .push(socket.as_str().to_owned());
        self.streams.lock().unwrap().pop_front().unwrap()
    }
}

fn socket() -> HostPath {
    HostPath::new(
        PathStyle::Windows,
        r"C:\Yougori\vm\0123456789abcdef\qmp.sock",
    )
    .unwrap()
}

#[test]
fn the_monitor_port_runs_one_session_per_call() {
    let status = status_reply(2, "running", true);
    let accelerators = accelerators_reply(2, "whpx", &["tcg", "whpx"]);
    let unknown = accelerators_reply(2, "qtest", &["qtest"]);
    let connect = ScriptedConnect::new(vec![
        Ok(Transcript::lines(&[
            GREETING,
            CAPABILITIES_OK,
            RESUME_EVENT,
            &status,
        ])),
        Ok(Transcript::lines(&[
            GREETING,
            CAPABILITIES_OK,
            &accelerators,
        ])),
        Ok(Transcript::lines(&[GREETING, CAPABILITIES_OK, &unknown])),
        // The real run's monitor skipped one event across its sessions: QEMU may send
        // SHUTDOWN before the reply to quit.
        Ok(Transcript::lines(&[
            GREETING,
            CAPABILITIES_OK,
            SHUTDOWN_EVENT,
            r#"{"return": {}, "id": 2}"#,
        ])),
        Err(QmpError::Connect {
            error: super::socket::SocketError::Os {
                operation: super::socket::SocketOperation::Connect,
                code: 10061,
            },
        }),
    ]);
    let mut monitor = QmpMonitor::new(&connect);
    assert_eq!(monitor.status(&socket()).unwrap(), RunState::Running);
    assert_eq!(monitor.accelerator(&socket()).unwrap(), "whpx");
    assert!(matches!(
        monitor.accelerator(&socket()),
        Err(MonitorFailure::Protocol { .. })
    ));
    monitor.quit(&socket()).unwrap();
    assert!(matches!(
        monitor.status(&socket()),
        Err(MonitorFailure::Unreachable { .. })
    ));
    assert_eq!(monitor.events_skipped(), 2);
    assert_eq!(connect.sockets.lock().unwrap().len(), 5);
    assert!(connect
        .sockets
        .lock()
        .unwrap()
        .iter()
        .all(|path| path == socket().as_str()));
}
