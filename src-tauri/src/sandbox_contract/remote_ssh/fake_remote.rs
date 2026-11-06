//! The fake remote control agent of the control transport's tests (tests only, Windows):
//! this test executable, started by [`ControlTransport`](super::ControlTransport) exactly
//! as the stock client would be, playing the client and the agent behind it at once.
//! Nothing here runs `ssh` or opens a socket.
//!
//! Like the fake client (`fake_client`), it starts from a CRT initializer of its own
//! (`.CRT$XCU`), which runs before `main` and before libtest reads its arguments. It
//! becomes the fake only when the first two arguments are `-F none`, `PATH` is absent (the
//! transport clears it; every cargo run has it) and the working directory holds
//! [`CONTROL_SCRIPT_FILE`]; the fake client looks for a script file of its own, so one
//! directory starts one of them. It then appends its process id to [`CONTROL_RUNS_FILE`]
//! and, unless its script fails before any session, reads the session key and the host's
//! first frame, checks that frame's seal under the key, writes a [`Record`] of what it was
//! given (stdin as read so far) to [`CONTROL_RECORD_FILE`], starts [`CONTROL_LOG_FILE`]
//! with that frame, and acts out its [`ControlScript`]. Its own frames are sealed under
//! the key, name the session and identity of the host's first frame and count from 0;
//! every later host frame must verify the same way, or the fake exits with
//! [`BAD_HOST_FRAME`], and is added to the log before the fake answers it.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::control_channel::{CONTROL_KEY_BYTES, MAX_CONTROL_FRAME_BYTES};
use super::fake_client::Record;
use crate::foundation::ids::{digest, Digest};
use crate::sandbox_contract::remote::{
    ControlBody, ControlFrame, ControlKey, ControlSessionId, SealedFrame,
};

/// The script file the fake looks for in its working directory.
pub const CONTROL_SCRIPT_FILE: &str = "fake-control-script.json";
/// The record the fake writes once it has read the key and the host's first frame.
pub const CONTROL_RECORD_FILE: &str = "fake-control-record.json";
/// The host frames the fake accepted, one JSON line each.
pub const CONTROL_LOG_FILE: &str = "fake-control-frames.jsonl";
/// One line per start of the fake: its process id.
pub const CONTROL_RUNS_FILE: &str = "fake-control-runs";

/// Exit codes of a fake that could not do its part.
const BAD_SCRIPT: i32 = 71;
const BAD_KEY: i32 = 72;
/// The host sent a frame that does not verify under the key, session and identity, or
/// does not count up.
pub const BAD_HOST_FRAME: i32 = 73;
const RECORD_FAILED: i32 = 74;
const WRITE_FAILED: i32 = 75;

/// A frame a misbehaving remote sends after its first heartbeat.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    /// A length one byte over the frame bound, and nothing after it.
    Oversize,
    /// A heartbeat whose sequence was changed after sealing.
    Tampered,
    /// The fake's first heartbeat, sent again.
    Replayed,
    /// A heartbeat for another session, sealed under the right key.
    OtherSession,
    /// A heartbeat naming another identity, sealed under the right key.
    StaleIdentity,
    /// A sealed heartbeat with one field more.
    UnknownField,
}

/// What the fake does once it has the key and the host's first frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "act", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum ControlScript {
    /// Answers the host's first frame with a heartbeat, then every grant: the first with
    /// a renewal request for its authority when `renew`, every other with a heartbeat.
    /// Exits with 0 when stdin closes.
    Serve { renew: bool },
    /// Answers the host's first frame with a heartbeat, sends `fault`, then reads stdin
    /// until it closes.
    Misbehave { fault: Fault },
    /// Answers the host's first frame with a heartbeat when `hello`, then exits with
    /// `code`.
    Exit { hello: bool, code: i32 },
    /// Answers the host's first frame with a heartbeat when `hello`, then sends nothing
    /// and reads stdin until it closes.
    Silent { hello: bool },
    /// Answers the host's first frame with a heartbeat, then neither reads nor writes for
    /// `seconds` and exits with 0.
    Deaf { seconds: u64 },
    /// Answers the host's first frame with a heartbeat, writes `bytes` bytes to stderr,
    /// then reads stdin until it closes.
    Chatter { bytes: u64 },
    /// Reads nothing, prints `stderr` and exits with `code`, as a client that failed
    /// before any session.
    Fail { stderr: String, code: i32 },
}

crate::foundation::strict_serde::strict_tag!(ControlScript, "act");

#[used]
#[link_section = ".CRT$XCU"]
static FAKE_REMOTE_ENTRY: extern "C" fn() = fake_remote_entry;

/// Runs before `main`; becomes the fake only when started as the transport starts a
/// client in a directory holding its script.
extern "C" fn fake_remote_entry() {
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
    let Ok(script) = std::fs::read(directory.join(CONTROL_SCRIPT_FILE)) else {
        return;
    };
    std::process::exit(act(&arguments, &directory, &script));
}

/// One length-prefixed message from `input`, appended to `seen`; `Ok(None)` when the
/// input ends between messages.
fn read_message(input: &mut impl Read, seen: &mut Vec<u8>) -> Result<Option<Vec<u8>>, ()> {
    let mut prefix = [0u8; 4];
    let mut first = [0u8; 1];
    match input.read(&mut first) {
        Ok(0) => return Ok(None),
        Ok(_) => prefix[0] = first[0],
        Err(_) => return Err(()),
    }
    input.read_exact(&mut prefix[1..]).map_err(|_| ())?;
    let length = u32::from_be_bytes(prefix);
    if length == 0 || length > MAX_CONTROL_FRAME_BYTES {
        return Err(());
    }
    let mut message = vec![0; usize::try_from(length).map_err(|_| ())?];
    input.read_exact(&mut message).map_err(|_| ())?;
    seen.extend_from_slice(&prefix);
    seen.extend_from_slice(&message);
    Ok(Some(message))
}

/// The remote's end of the session, as the fake plays it.
struct Remote {
    key: ControlKey,
    session: ControlSessionId,
    identity: Digest,
    next: u64,
    last_host: u64,
    sent: Vec<SealedFrame>,
}

impl Remote {
    fn seal(&mut self, body: ControlBody) -> SealedFrame {
        let sealed = ControlFrame {
            session: self.session,
            identity: self.identity,
            sequence: self.next,
            body,
        }
        .seal(&self.key);
        self.next += 1;
        sealed
    }

    /// Whether `sealed` is the host's next frame on this session.
    fn verifies(&self, sealed: &SealedFrame) -> bool {
        sealed.frame.seal(&self.key) == *sealed
            && sealed.frame.session == self.session
            && sealed.frame.identity == self.identity
            && sealed.frame.sequence > self.last_host
    }

    fn send(&mut self, body: ControlBody) -> bool {
        let sealed = self.seal(body);
        self.sent.push(sealed);
        write_json(&sealed)
    }
}

/// Writes `bytes` behind their length to stdout.
fn write_message(bytes: &[u8]) -> bool {
    let Ok(length) = u32::try_from(bytes.len()) else {
        return false;
    };
    let mut out = std::io::stdout().lock();
    out.write_all(&length.to_be_bytes())
        .and_then(|()| out.write_all(bytes))
        .and_then(|()| out.flush())
        .is_ok()
}

fn write_json(value: &impl Serialize) -> bool {
    serde_json::to_vec(value).is_ok_and(|json| write_message(&json))
}

fn log(directory: &Path, frame: &SealedFrame, fresh: bool) -> bool {
    let Ok(mut line) = serde_json::to_string(frame) else {
        return false;
    };
    line.push('\n');
    let mut options = OpenOptions::new();
    if fresh {
        options.write(true).create(true).truncate(true);
    } else {
        options.append(true).create(true);
    }
    options
        .open(directory.join(CONTROL_LOG_FILE))
        .and_then(|mut file| file.write_all(line.as_bytes()))
        .is_ok()
}

/// Writes the record to a temporary name first, so a reader never sees half of it.
fn write_record(arguments: &[OsString], directory: &Path, stdin: Vec<u8>) -> bool {
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
    let partial = directory.join(format!("{CONTROL_RECORD_FILE}.partial"));
    serde_json::to_vec(&record).is_ok_and(|json| {
        std::fs::write(&partial, json).is_ok()
            && std::fs::rename(&partial, directory.join(CONTROL_RECORD_FILE)).is_ok()
    })
}

/// Reads stdin until it closes.
fn drain(input: &mut impl Read) {
    let _ = std::io::copy(input, &mut std::io::sink());
}

fn act(arguments: &[OsString], directory: &Path, script: &[u8]) -> i32 {
    let _ = OpenOptions::new()
        .append(true)
        .create(true)
        .open(directory.join(CONTROL_RUNS_FILE))
        .and_then(|mut file| writeln!(file, "{}", std::process::id()));
    let Ok(script) = serde_json::from_slice::<ControlScript>(script) else {
        return BAD_SCRIPT;
    };
    if let ControlScript::Fail { stderr, code } = &script {
        let _ = std::io::stderr().lock().write_all(stderr.as_bytes());
        return *code;
    }
    let mut input = std::io::stdin().lock();
    let mut seen = Vec::new();
    let key = match read_message(&mut input, &mut seen) {
        Ok(Some(bytes)) if bytes.len() == CONTROL_KEY_BYTES => ControlKey::new(bytes),
        _ => return BAD_KEY,
    };
    let Ok(key) = key else {
        return BAD_KEY;
    };
    let hello = match read_message(&mut input, &mut seen) {
        Ok(Some(bytes)) => serde_json::from_slice::<SealedFrame>(&bytes),
        _ => return BAD_HOST_FRAME,
    };
    let Ok(hello) = hello else {
        return BAD_HOST_FRAME;
    };
    if hello.frame.seal(&key) != hello
        || hello.frame.sequence != 0
        || hello.frame.body != ControlBody::Heartbeat
    {
        return BAD_HOST_FRAME;
    }
    if !write_record(arguments, directory, seen) || !log(directory, &hello, true) {
        return RECORD_FAILED;
    }
    let mut remote = Remote {
        key,
        session: hello.frame.session,
        identity: hello.frame.identity,
        next: 0,
        last_host: 0,
        sent: Vec::new(),
    };
    match script {
        ControlScript::Serve { renew } => serve(&mut remote, &mut input, directory, renew),
        ControlScript::Misbehave { fault } => {
            if !remote.send(ControlBody::Heartbeat) || !misbehave(&mut remote, fault) {
                return WRITE_FAILED;
            }
            drain(&mut input);
            0
        }
        ControlScript::Exit { hello, code } => {
            if hello && !remote.send(ControlBody::Heartbeat) {
                return WRITE_FAILED;
            }
            code
        }
        ControlScript::Silent { hello } => {
            if hello && !remote.send(ControlBody::Heartbeat) {
                return WRITE_FAILED;
            }
            drain(&mut input);
            0
        }
        ControlScript::Deaf { seconds } => {
            if !remote.send(ControlBody::Heartbeat) {
                return WRITE_FAILED;
            }
            std::thread::sleep(std::time::Duration::from_secs(seconds));
            0
        }
        ControlScript::Chatter { bytes } => {
            let chatter = vec![b'x'; usize::try_from(bytes).unwrap_or(0)];
            let mut error = std::io::stderr().lock();
            if !remote.send(ControlBody::Heartbeat)
                || error
                    .write_all(&chatter)
                    .and_then(|()| error.flush())
                    .is_err()
            {
                return WRITE_FAILED;
            }
            drain(&mut input);
            0
        }
        ControlScript::Fail { code, .. } => code,
    }
}

fn serve(remote: &mut Remote, input: &mut impl Read, directory: &Path, renew: bool) -> i32 {
    if !remote.send(ControlBody::Heartbeat) {
        return WRITE_FAILED;
    }
    let mut asked = !renew;
    let mut ignored = Vec::new();
    loop {
        let sealed = match read_message(input, &mut ignored) {
            Ok(Some(bytes)) => serde_json::from_slice::<SealedFrame>(&bytes),
            Ok(None) => return 0,
            Err(()) => return BAD_HOST_FRAME,
        };
        let Ok(sealed) = sealed else {
            return BAD_HOST_FRAME;
        };
        if !remote.verifies(&sealed) || !log(directory, &sealed, false) {
            return BAD_HOST_FRAME;
        }
        remote.last_host = sealed.frame.sequence;
        let answered = match sealed.frame.body {
            ControlBody::Grant { grant } if !asked => {
                asked = true;
                remote.send(ControlBody::RenewalRequest {
                    authority: grant.authority,
                    clock: grant.clock,
                })
            }
            ControlBody::Grant { .. } => remote.send(ControlBody::Heartbeat),
            ControlBody::Stop => return 0,
            _ => true,
        };
        if !answered {
            return WRITE_FAILED;
        }
    }
}

fn misbehave(remote: &mut Remote, fault: Fault) -> bool {
    match fault {
        Fault::Oversize => write_message_prefix(MAX_CONTROL_FRAME_BYTES + 1),
        Fault::Tampered => {
            let mut sealed = remote.seal(ControlBody::Heartbeat);
            sealed.frame.sequence += 1;
            write_json(&sealed)
        }
        Fault::Replayed => {
            let first = remote.sent[0];
            write_json(&first)
        }
        Fault::OtherSession => {
            let sealed = ControlFrame {
                session: ControlSessionId::new(digest("yougori/test/other-session/v1", &[])),
                identity: remote.identity,
                sequence: remote.next,
                body: ControlBody::Heartbeat,
            }
            .seal(&remote.key);
            write_json(&sealed)
        }
        Fault::StaleIdentity => {
            let sealed = ControlFrame {
                session: remote.session,
                identity: digest("yougori/test/other-identity/v1", &[]),
                sequence: remote.next,
                body: ControlBody::Heartbeat,
            }
            .seal(&remote.key);
            write_json(&sealed)
        }
        Fault::UnknownField => {
            let sealed = remote.seal(ControlBody::Heartbeat);
            let Ok(mut value) = serde_json::to_value(sealed) else {
                return false;
            };
            value["note"] = serde_json::json!("one field more");
            write_json(&value)
        }
    }
}

/// Writes only a length prefix of `length`.
fn write_message_prefix(length: u32) -> bool {
    let mut out = std::io::stdout().lock();
    out.write_all(&length.to_be_bytes())
        .and_then(|()| out.flush())
        .is_ok()
}
