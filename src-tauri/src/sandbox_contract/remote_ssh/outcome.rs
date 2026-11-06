//! The SSH command port and the classification of what the OpenSSH client reported
//! (VM-W41; VM part §6.3 step 5: uncertain outcomes are recorded as uncertain; VM-CP-33
//! and VM-P42: nothing unproven passes as success).
//!
//! The OpenSSH client exits with the remote command's status, or 255 for its own errors.
//! [`classify`] therefore reads 0–254 as the remote exit code and reads stderr only for
//! 255. On 255 it recognises the last line or two of stderr, compared whole, never by
//! substring, and with the target's host, port, `known_hosts` pattern, account and
//! identity file filled in where OpenSSH prints them:
//!
//! | stderr ends with | outcome |
//! |---|---|
//! | `Host key verification failed.` (with `<TYPE> host key for <pattern> has changed and you have requested strict checking.` earlier for `Changed`) | host-key mismatch |
//! | `Unable to negotiate with <addr> port <port>: no matching host key type found. ...` | host-key mismatch (the enrolled algorithm is not offered) |
//! | `[<account>@<host>: ]Permission denied (<methods>).` | authentication refused |
//! | `ssh: connect to host <host> port <port>: <reason>` | connection failed, or a connect timeout for `Connection timed out` / `Operation timed out` |
//! | `ssh: Could not resolve hostname <host>: <reason>` | connection failed (name) |
//! | `Connection timed out during banner exchange` | connect timeout |
//! | `kex_exchange_identification: ...` | connection failed (handshake) |
//! | `Unable to negotiate with <addr> port <port>: no matching <other> found. ...` | connection failed (negotiation) |
//! | `Timeout, server <host> not responding.` | timeout after connecting |
//! | `Connection to <host> closed by remote host.` | uncertain (connection lost) |
//!
//! Every message comes from OpenSSH 8.x/9.x client sources as remembered, not from a test
//! against a real client (none is run here); wording that differs falls to `Uncertain`,
//! never to success. OpenSSH ends its log lines with CRLF; both endings are read.
//!
//! Before the status: a client not started is a connection failure, the deadline a
//! timeout, and a local fault of the port after the start ([`PortFailure`]) is
//! `Uncertain` with V12's `AmbiguousResponse` (the command may have run and its result was
//! not read), never `ConnectionLost`, which is kept for a client that ended without a
//! status.
//!
//! Limit: after authentication the client's stderr also carries the remote command's
//! stderr, so a remote command that prints one of these lines last and exits 255 is
//! misread. Management helpers must not exit 255.

use serde::Serialize;

use super::invocation::SshInvocation;
use super::wire::is_openssh_sha256;
use crate::sandbox_contract::remote::{HostKeyFingerprint, RemoteHostId, UncertainCause};

/// The exit status OpenSSH uses for its own errors.
pub const SSH_CLIENT_ERROR_STATUS: i32 = 255;
/// The longest authentication method list recognised.
const MAX_METHODS_BYTES: usize = 256;

/// Runs a rendered invocation. [`ProcessSshPort`](super::ProcessSshPort) starts the
/// client; the classification tests use a fake that checks the argv.
///
/// An implementation starts the OpenSSH client with exactly
/// [`SshInvocation::arguments`], with an environment holding nothing secret (best,
/// cleared apart from what the platform needs to start a process) and a working
/// directory with no file named `none`; writes [`SshInvocation::stdin`] and closes stdin
/// (an invocation without stdin gets an empty one); stops the client at the limits'
/// deadline; and reads at most one byte more than each output bound.
pub trait SshPort {
    fn run(&mut self, invocation: &SshInvocation<'_>) -> SshOutput;
}

/// How the client ended, as the port saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "termination", rename_all = "snake_case")]
pub enum SshTermination {
    /// The client exited with this status.
    Exited { code: i32 },
    /// The client ended without an exit status, such as by a signal.
    NoExitStatus,
    /// The port stopped the client at the deadline.
    DeadlineReached,
    /// The client could not be started; nothing was sent.
    NotStarted,
    /// The client started, but the port could not feed it, read it or watch it, so it
    /// killed it and did not see its result.
    PortFailed { failure: PortFailure },
}

/// What failed in the port after the client started: a local fault, not anything the
/// client, the network or the host reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PortFailure {
    /// A pipe to the client was missing.
    PipeMissing,
    /// A thread to write the client's stdin or read its output could not start.
    ThreadNotStarted,
    /// Reading an output stream failed, so the output was not seen whole.
    ReadFailed,
    /// Asking the system whether the client had ended failed.
    WaitFailed,
}

/// What the port reports: how the client ended and what it printed, each stream cut at
/// one byte over its bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshOutput {
    pub termination: SshTermination,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// One output stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// Why no session was established. In every case the remote command did not start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionFailure {
    /// The port could not start the client.
    ClientNotStarted,
    NameNotResolved,
    Refused,
    Unreachable,
    /// The TCP connection failed for another reason the client named.
    ConnectFailed,
    /// The SSH identification exchange failed.
    Handshake,
    /// No common key exchange, cipher or MAC.
    Negotiation,
}

/// When a time limit ran out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutPhase {
    /// Connecting or the banner exchange: the remote command did not start.
    Connect,
    /// The server stopped answering keepalives after connecting.
    ServerUnresponsive,
    /// The port stopped the client at the deadline.
    Deadline,
}

/// What the client reported about the host key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "evidence", rename_all = "snake_case")]
pub enum HostKeyEvidence {
    /// The host presented another key than the enrolled one; `reported` is OpenSSH's
    /// SHA256 fingerprint of it, when printed.
    Changed { reported: Option<String> },
    /// The host does not offer the enrolled algorithm, so it cannot present the
    /// enrolled key.
    AlgorithmNotOffered,
    /// Verification failed without a recognised reason, such as no matching line.
    Unverified,
}

/// A classified run.
///
/// [`SshOutcome::HostKeyMismatch`] is the situation of V12's
/// [`HostKeyRefusal::Changed`](crate::sandbox_contract::remote::HostKeyRefusal::Changed)
/// and ends delegation the same way: no session, nothing renewed, the enrollment left as
/// it is, so delegated authority runs out. It carries V12's host and enrolled
/// fingerprint; V12's `presented` fingerprint cannot be filled, because the client never
/// hands over the key it was shown (only its SHA256, kept as `reported`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SshOutcome {
    /// The remote command ran and exited with `code`; 0 is the only success.
    RemoteExit {
        code: u8,
    },
    /// The host key is not the enrolled one.
    HostKeyMismatch {
        host: RemoteHostId,
        enrolled: HostKeyFingerprint,
        evidence: HostKeyEvidence,
    },
    /// The server refused the client key.
    AuthenticationRefused {
        methods: String,
        /// The client also reported that it could not load the identity file.
        identity_file_unusable: bool,
    },
    ConnectionFailed {
        failure: ConnectionFailure,
    },
    TimedOut {
        phase: TimeoutPhase,
    },
    /// A stream exceeded its bound, so the result was not seen whole.
    OutputOverBound {
        stream: OutputStream,
        max_bytes: u64,
    },
    /// The remote command may or may not have run, or may not have finished.
    Uncertain {
        cause: UncertainCause,
    },
}

impl SshOutcome {
    /// True only for a remote exit status of 0.
    pub fn succeeded(&self) -> bool {
        matches!(self, Self::RemoteExit { code: 0 })
    }

    /// Whether the remote command may have started. False only where the client
    /// failed before any session existed.
    pub fn command_may_have_run(&self) -> bool {
        match self {
            Self::RemoteExit { .. } | Self::OutputOverBound { .. } | Self::Uncertain { .. } => true,
            Self::TimedOut { phase } => *phase != TimeoutPhase::Connect,
            Self::HostKeyMismatch { .. }
            | Self::AuthenticationRefused { .. }
            | Self::ConnectionFailed { .. } => false,
        }
    }

    /// Whether this outcome ends delegation, as V12's host-key refusal does.
    pub fn ends_delegation(&self) -> bool {
        matches!(self, Self::HostKeyMismatch { .. })
    }
}

fn over(stream: &[u8], max_bytes: u64) -> bool {
    u64::try_from(stream.len()).unwrap_or(u64::MAX) > max_bytes
}

/// Classifies what the port reported for `invocation`; see the module notes.
pub fn classify(invocation: &SshInvocation<'_>, output: &SshOutput) -> SshOutcome {
    let limits = invocation.limits();
    let code = match output.termination {
        SshTermination::NotStarted => return failed(ConnectionFailure::ClientNotStarted),
        SshTermination::DeadlineReached => return timed_out(TimeoutPhase::Deadline),
        // A local fault after the start: the command may have run and its result was not
        // read, which is V12's ambiguous response, not a lost connection.
        SshTermination::PortFailed { .. } => return uncertain(UncertainCause::AmbiguousResponse),
        SshTermination::NoExitStatus => None,
        SshTermination::Exited { code } => Some(code),
    };
    for (stream, bytes, max_bytes) in [
        (
            OutputStream::Stdout,
            &output.stdout,
            limits.max_stdout_bytes(),
        ),
        (
            OutputStream::Stderr,
            &output.stderr,
            limits.max_stderr_bytes(),
        ),
    ] {
        if over(bytes, max_bytes) {
            return SshOutcome::OutputOverBound { stream, max_bytes };
        }
    }
    match code {
        // The client vanished without a status: the command may have run.
        None => uncertain(UncertainCause::ConnectionLost),
        Some(SSH_CLIENT_ERROR_STATUS) => classify_client_error(invocation, &output.stderr),
        // 0–254 is the remote status; anything else (a crashed client on Windows, say)
        // is no status OpenSSH reports.
        Some(code) => match u8::try_from(code) {
            Ok(code) => SshOutcome::RemoteExit { code },
            Err(_) => uncertain(UncertainCause::AmbiguousResponse),
        },
    }
}

fn uncertain(cause: UncertainCause) -> SshOutcome {
    SshOutcome::Uncertain { cause }
}

fn failed(failure: ConnectionFailure) -> SshOutcome {
    SshOutcome::ConnectionFailed { failure }
}

fn timed_out(phase: TimeoutPhase) -> SshOutcome {
    SshOutcome::TimedOut { phase }
}

/// An OpenSSH key type word such as `ED25519`, `ECDSA` or `RSA`.
fn is_key_type_word(word: &str) -> bool {
    !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn host_key_evidence(lines: &[&str], pattern: &str) -> HostKeyEvidence {
    let changed =
        format!(" host key for {pattern} has changed and you have requested strict checking.");
    let is_changed = lines.iter().any(|line| {
        line.strip_suffix(changed.as_str())
            .is_some_and(is_key_type_word)
    });
    if !is_changed {
        return HostKeyEvidence::Unverified;
    }
    let reported = lines.windows(2).find_map(|pair| match pair {
        [intro, fingerprint]
            if intro.starts_with("The fingerprint for the ")
                && intro.ends_with(" key sent by the remote host is") =>
        {
            fingerprint
                .strip_suffix('.')
                .filter(|fingerprint| is_openssh_sha256(fingerprint))
                .map(str::to_owned)
        }
        _ => None,
    });
    HostKeyEvidence::Changed { reported }
}

fn permission_denied<'l>(line: &'l str, account: &str, host: &str) -> Option<&'l str> {
    let prefix = format!("{account}@{host}: ");
    let rest = line.strip_prefix(prefix.as_str()).unwrap_or(line);
    let methods = rest
        .strip_prefix("Permission denied (")?
        .strip_suffix(").")?;
    let valid = !methods.is_empty()
        && methods.len() <= MAX_METHODS_BYTES
        && methods.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b',' | b'@' | b'.')
        });
    valid.then_some(methods)
}

fn classify_client_error(invocation: &SshInvocation<'_>, stderr: &[u8]) -> SshOutcome {
    let text = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter(|line| !line.trim().is_empty())
        .collect();
    let Some(&last) = lines.last() else {
        return uncertain(UncertainCause::AmbiguousResponse);
    };
    let previous = lines
        .len()
        .checked_sub(2)
        .and_then(|index| lines.get(index))
        .copied();
    let target = invocation.target();
    let host = target.command_host();
    let port = target.port();

    if last == "Host key verification failed." {
        return SshOutcome::HostKeyMismatch {
            host: target.host(),
            enrolled: invocation.enrolled(),
            evidence: host_key_evidence(&lines, &target.known_hosts_pattern()),
        };
    }
    if let Some(rest) = last.strip_prefix("Unable to negotiate with ") {
        let marker = format!(" port {port}: no matching ");
        if let Some((_, kind)) = rest.split_once(marker.as_str()) {
            if kind.starts_with("host key type found.") {
                return SshOutcome::HostKeyMismatch {
                    host: target.host(),
                    enrolled: invocation.enrolled(),
                    evidence: HostKeyEvidence::AlgorithmNotOffered,
                };
            }
            if kind.contains(" found.") {
                return failed(ConnectionFailure::Negotiation);
            }
        }
    }
    if let Some(methods) = permission_denied(last, invocation.account().as_str(), &host) {
        let load_key = format!("Load key \"{}\": ", invocation.identity_file());
        return SshOutcome::AuthenticationRefused {
            methods: methods.to_owned(),
            identity_file_unusable: lines.iter().any(|line| line.starts_with(&load_key)),
        };
    }
    if let Some(reason) = last.strip_prefix(&format!("ssh: connect to host {host} port {port}: ")) {
        return match reason {
            "Connection refused" => failed(ConnectionFailure::Refused),
            "No route to host" | "Network is unreachable" => failed(ConnectionFailure::Unreachable),
            "Connection timed out" | "Operation timed out" => timed_out(TimeoutPhase::Connect),
            _ => failed(ConnectionFailure::ConnectFailed),
        };
    }
    // OpenSSH prints at most 100 bytes of the name here.
    let shown = host.get(..100).unwrap_or(&host);
    if ["ssh", "ssh.exe"].iter().any(|program| {
        last.starts_with(&format!("{program}: Could not resolve hostname {shown}: "))
    }) {
        return failed(ConnectionFailure::NameNotResolved);
    }
    const BANNER_TIMEOUT: &str = "Connection timed out during banner exchange";
    if last == BANNER_TIMEOUT
        || (previous == Some(BANNER_TIMEOUT)
            && last.starts_with("Connection to ")
            && last.ends_with(&format!(" port {port} timed out")))
    {
        return timed_out(TimeoutPhase::Connect);
    }
    const IDENTIFICATION: &str = "kex_exchange_identification: ";
    if last.starts_with(IDENTIFICATION)
        || (previous.is_some_and(|line| line.starts_with(IDENTIFICATION))
            && (last.starts_with("Connection closed by ")
                || last.starts_with("Connection reset by "))
            && last.ends_with(&format!(" port {port}")))
    {
        return failed(ConnectionFailure::Handshake);
    }
    if last == format!("Timeout, server {host} not responding.") {
        return timed_out(TimeoutPhase::ServerUnresponsive);
    }
    if last == format!("Connection to {host} closed by remote host.") {
        return uncertain(UncertainCause::ConnectionLost);
    }
    uncertain(UncertainCause::AmbiguousResponse)
}
