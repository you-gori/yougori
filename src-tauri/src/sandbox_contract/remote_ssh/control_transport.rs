//! M16G: the control session's transport over SSH, and its session key (M16 (c3); VM-W39
//! "loss of control connection", "stale identities"; VM-W41 "remote reconnect cannot
//! revive expired authority", "host-key changes rejected";
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §6.3; VM part §4.5).
//!
//! V12's control session (`remote/control.rs`) authenticates every frame between the home
//! host and one remote host with HMAC-SHA256 under a session key it takes as an input,
//! and V12's adapter (`remote/adapter.rs`) renews delegated authority only over a live
//! session. This module makes the key and carries the frames: [`ControlTransport`] runs
//! one [`ControlChannel`](super::ControlChannel) per session, a long-lived run of the
//! stock OpenSSH client running the remote control agent ([`ControlAgent`], a configured
//! program; the packaged engine provides `--sandbox-remote-agent`), and hands every frame to V12,
//! which stays the judge of state, sequence, replay, identity and seal.
//!
//! The session key. For every session the home host draws [`CONTROL_KEY_BYTES`] fresh
//! bytes from the operating system's CSPRNG (`ring::rand::SystemRandom`) and sends them
//! as the first, length-prefixed message on the client's stdin, before any frame (the
//! wire format is in `control_channel`). No further key exchange is added, because the
//! SSH channel the key travels in already is one, authenticated and encrypted. Sending
//! the key in it relies on:
//!
//! - the host key: the client accepts only the enrolled key (`StrictHostKeyChecking=yes`,
//!   the rendered `known_hosts` file holding that one key, the enrolled algorithm only),
//!   so the key reaches only the holder of the enrolled host's private key, as far as the
//!   enrollment's recorded trust assumptions hold;
//! - the management identity: the server runs the agent only for the management
//!   account's client key, so the key reaches only that account's command on that host;
//! - SSH's own key exchange and ciphers, which keep the channel secret and unaltered; a
//!   recording of the connection yields the key only if SSH's own session keys leak;
//! - the ends: the local client binary, this process and the pipe between them, and on
//!   the remote host sshd, the account's login shell, the agent and anyone who is root or
//!   that account there, all of whom can read the key;
//! - the CSPRNG, for keys that no earlier session shares.
//!
//! The key never goes into an argument (it is drawn only after the argv is rendered from
//! V12's typed values, so nothing can carry it there; the argv is not scanned for it,
//! because a scan would leave encoded copies of the key that nothing overwrites), the
//! environment (the client's is cleared), `Debug`, `Display` or an error (V12's
//! `ControlKey` redacts itself, and nothing here shows what it sends). The buffers this
//! module fills with it are overwritten once the key is handed to V12 and written to the
//! pipe, best effort as in `process`: V12's `ControlKey` keeps its own copy for the
//! session's life and does not overwrite it, and the pipe and the client hold copies out
//! of reach.
//!
//! The session id is the digest of 32 more fresh bytes under [`CONTROL_SESSION_DOMAIN`].
//! V12's public binding of the session (`ControlSession::session_key`, which an
//! attestation report must name) is the digest of the session id and the key under
//! [`CONTROL_BINDING_DOMAIN`]: the remote can compute it, and it reveals nothing of the
//! key. Right after the key the host sends its first frame, a heartbeat sealed on the new
//! session (its sequence 0), which tells the remote the session id and the identity
//! digest every frame must name, under a seal only the key's holder can check. The
//! remote's frames follow on stdout, its sequence 0 first.
//!
//! Opening ([`ControlTransport::open`]); nothing is started until V12 has taken the
//! session:
//!
//! 1. Refused while a channel is open, and for good once a channel met another host key.
//! 2. As [`ManagementChannel`](super::ManagementChannel) checks: the identity file is
//!    still owner-only; the adapter has an enrolled identity, on the management
//!    identity's host; the run is a VM run, since the agent runs as a supervise call in
//!    the host shell, the only context V12 runs supervise in.
//! 3. V12's checks through [`render_invocation`]: the management identity is current and
//!    may supervise, and the `known_hosts` file holds the host's current enrollment.
//! 4. The key, the session id, V12's `ControlSession` and the host's first frame.
//! 5. The working directory, checked as the process port checks it.
//! 6. V12's [`RemoteVmAdapter::connect`]: it refuses outside runtime-confirmed and
//!    running, refuses a stale identity, and while running checks the host's authority
//!    first, so a reconnect never revives authority that ended. It is shown the enrolled
//!    key: the client checks the key the host presents itself, against a file holding
//!    only the enrolled one, and goes no further with any other.
//! 7. The client is started and the key and first frame written to it.
//! 8. The remote's first frame, due within the silence deadline, is handed to V12.
//!
//! Driving. [`ControlTransport::launch`] and [`ControlTransport::renew`] seal V12's grant
//! and send it; [`ControlTransport::receive`] hands each frame to
//! [`RemoteVmAdapter::handle_frame`], whose `ControlSession::accept` judges the seal, the
//! session, the identity and the sequence, and sends at once a renewal V12 grants. A
//! status report is returned for the caller to judge with
//! [`RemoteVmAdapter::observe_remote_expiry`], which needs a wall-clock observation made
//! outside this module.
//!
//! Ending. Every end of the channel (see `control_channel`) and every V12 refusal of a
//! frame or step ends the session: the client is closed or killed, its stderr classified,
//! and the adapter's session, while it is still this one, marked lost through
//! [`RemoteVmAdapter::connection_lost`]. A host-key mismatch the client reports is first
//! reported through [`RemoteVmAdapter::report_host_key_mismatch`] (V12 records the
//! rejection, as observed by management SSH, and ends delegated authority at once), and
//! the transport opens nothing more. A lost session is never resumed: nothing is sent on
//! its channel again, and reconnecting is a new open with a new client, key, session id
//! and V12 session, judged afresh; frames of the old session fail the new one's seal.
//! [`ControlTransport::close`] ends the channel the same way; a transport dropped with a
//! channel open kills its client, and V12's session then goes silent.
//!
//! Not here: the remote agent (M16 (c1)), which must read the key and the host's first
//! frame, answer with sealed frames often enough to stay within the silence deadline, and
//! keep its stderr quiet; the product wiring (M16 (c2)); a provider-container run, for
//! which V12 has no action that runs an agent inside the container; and any check against
//! a real OpenSSH client or server (E01). The remote's stderr shares the client's, so a
//! remote that prints OpenSSH's host-key failure and exits with 255 is read as a mismatch
//! (see `outcome`); it can end its own run's authority and nothing else. Tier 0: tested
//! with this test executable as the client and the remote agent (Windows only); nothing
//! here proves anything about a real client, server or network.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;

use super::control_channel::{
    encode, framed, ControlChannel, ControlEndReason, CONTROL_KEY_BYTES, MAX_CONTROL_FRAME_BYTES,
};
use super::invocation::{render_invocation, IdentityFile, SshLimits, SshRenderRefusal};
use super::known_hosts::KnownHostsFile;
use super::management::{context_fits, rejection_evidence, RejectedHostKey};
use super::outcome::{SshOutcome, SshTermination};
use super::process::{check_program, check_working_directory, PayloadCopy, SshClientRefusal};
use super::protection::{check_identity_file, IdentityFileRefusal};
use crate::foundation::ids::{Clock, DigestBuilder, MonotonicTime, OperationId};
use crate::sandbox_contract::remote::{
    AdapterRefusal, ArgvRefusal, AttestationRecord, ControlBody, ControlKey, ControlRefusal,
    ControlSession, ControlSessionId, ExecutionContext, FrameOutcome, HostAuthority,
    HostKeyFingerprint, KnownHosts, ManagementAction, ManagementIdentity, OptionTerminator,
    ProgramPath, RemoteCommand, RemoteHostId, RemoteIdentity, RemoteInvocation, RemoteVmAdapter,
    SealedFrame,
};

/// Domain of a control session's id, a digest of fresh random bytes.
pub const CONTROL_SESSION_DOMAIN: &str = "yougori/remote-ssh/control-session/v1";
/// Domain of a control session's public binding: the session id and the key.
pub const CONTROL_BINDING_DOMAIN: &str = "yougori/remote-ssh/control-binding/v1";
/// The longest silence deadline accepted.
pub const MAX_CONTROL_SILENCE: Duration = Duration::from_secs(3_600);
/// The longest write wait accepted.
pub const MAX_WRITE_WAIT: Duration = Duration::from_secs(600);

/// The bytes drawn for a session id.
const SESSION_NONCE_BYTES: usize = 32;

/// Why control limits were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ControlLimitsRefusal {
    /// The silence deadline is outside `min_seconds..=max_seconds`.
    SilenceOutOfRange { min_seconds: u64, max_seconds: u64 },
    /// The silence deadline would end the channel before the client's connect timeout.
    SilenceBeforeConnectTimeout,
    /// The write wait is outside `min_millis..=max_millis`.
    WriteWaitOutOfRange { min_millis: u64, max_millis: u64 },
}

impl fmt::Display for ControlLimitsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SilenceOutOfRange {
                min_seconds,
                max_seconds,
            } => write!(
                f,
                "the control silence deadline must be between {min_seconds} s and {max_seconds} s"
            ),
            Self::SilenceBeforeConnectTimeout => {
                f.write_str("the control silence deadline must be at least the connect timeout")
            }
            Self::WriteWaitOutOfRange {
                min_millis,
                max_millis,
            } => write!(
                f,
                "the control write wait must be between {min_millis} ms and {max_millis} ms"
            ),
        }
    }
}

impl std::error::Error for ControlLimitsRefusal {}

/// The limits of a control channel: the SSH limits it is rendered with (the connect
/// timeout and keepalives go into the argv, the stderr bound holds for the channel's
/// life), how long it may stay silent, and how long a write may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ControlLimits {
    ssh: SshLimits,
    max_silence: Duration,
    write_wait: Duration,
}

impl ControlLimits {
    /// The standard SSH limits, a frame at least every 60 s and 10 s per write.
    pub const STANDARD: Self = Self {
        ssh: SshLimits::STANDARD,
        max_silence: Duration::from_secs(60),
        write_wait: Duration::from_secs(10),
    };

    /// Checks the silence deadline (1 s to [`MAX_CONTROL_SILENCE`], and not shorter than
    /// the connect timeout, since the remote's first frame is due within it) and the
    /// write wait (1 ms to [`MAX_WRITE_WAIT`]).
    pub fn new(
        ssh: SshLimits,
        max_silence: Duration,
        write_wait: Duration,
    ) -> Result<Self, ControlLimitsRefusal> {
        if max_silence < Duration::from_secs(1) || max_silence > MAX_CONTROL_SILENCE {
            return Err(ControlLimitsRefusal::SilenceOutOfRange {
                min_seconds: 1,
                max_seconds: MAX_CONTROL_SILENCE.as_secs(),
            });
        }
        if max_silence < Duration::from_secs(u64::from(ssh.connect_timeout_seconds())) {
            return Err(ControlLimitsRefusal::SilenceBeforeConnectTimeout);
        }
        if write_wait < Duration::from_millis(1) || write_wait > MAX_WRITE_WAIT {
            return Err(ControlLimitsRefusal::WriteWaitOutOfRange {
                min_millis: 1,
                max_millis: u64::try_from(MAX_WRITE_WAIT.as_millis()).unwrap_or(u64::MAX),
            });
        }
        Ok(Self {
            ssh,
            max_silence,
            write_wait,
        })
    }

    /// The SSH limits the client is rendered with.
    pub fn ssh(&self) -> SshLimits {
        self.ssh
    }

    /// The longest time without a frame from the remote, the first one included.
    pub fn max_silence(&self) -> Duration {
        self.max_silence
    }

    /// The longest a message may take to be written to the client.
    pub fn write_wait(&self) -> Duration {
        self.write_wait
    }
}

/// A typed remote control invocation. A dedicated executable uses no arguments;
/// the packaged engine agent binds an existing engine endpoint and sandbox ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlAgent {
    command: RemoteCommand,
}

impl ControlAgent {
    /// The agent at `program` on the remote host.
    pub fn new(program: ProgramPath) -> Self {
        Self {
            command: RemoteCommand::new(program, OptionTerminator::NotSupported),
        }
    }

    /// No secret is an operand. Endpoint and execution remain literal argv under
    /// V12's single POSIX encoder; the key follows on authenticated stdin later.
    pub fn for_engine(
        program: ProgramPath,
        endpoint: &str,
        sandbox: &crate::foundation::ids::ExecutionId,
    ) -> Result<Self, ArgvRefusal> {
        let command = RemoteCommand::new(program, OptionTerminator::NotSupported)
            .flag("--sandbox-remote-agent")?
            .operand(endpoint)?
            .operand(sandbox.as_str())?;
        Ok(Self { command })
    }

    pub fn program(&self) -> &ProgramPath {
        self.command.program()
    }

    /// V12's invocation of the agent for `identity`'s host: a supervise call in the host
    /// shell, without stdin, built by V12 under a current identity that may supervise.
    pub fn invocation(
        &self,
        identity: &ManagementIdentity,
        known: &KnownHosts,
    ) -> Result<ControlInvocation, ArgvRefusal> {
        RemoteInvocation::new(
            identity,
            known,
            ManagementAction::SuperviseVm,
            ExecutionContext::RemoteHostShell {
                host: identity.host(),
            },
            &self.command,
        )
        .map(|invocation| ControlInvocation { invocation })
    }
}

/// V12's invocation of the control agent; only [`ControlAgent::invocation`] makes one.
#[derive(Debug)]
pub struct ControlInvocation {
    invocation: RemoteInvocation,
}

impl ControlInvocation {
    /// The V12 invocation, rendered again for every channel.
    pub fn remote(&self) -> &RemoteInvocation {
        &self.invocation
    }
}

/// How a control session ended. V12's session was marked lost, and, for a host-key
/// mismatch, the rejection reported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ControlEnd {
    /// The session the channel carried.
    pub session: ControlSessionId,
    /// Why the channel ended.
    pub reason: ControlEndReason,
    /// How the client ended.
    pub termination: SshTermination,
    /// What the client wrote to stderr, at most one byte over its bound.
    pub stderr: Vec<u8>,
    /// The classification of the client's end.
    pub outcome: SshOutcome,
    /// The host key the client met instead of the enrolled one, if it reported one.
    pub host_key: Option<RejectedHostKey>,
    /// When the end was reported, on the host authority's clock.
    pub ended_at: MonotonicTime,
}

/// Why a control step did nothing, or how the session ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlTransportRefusal {
    /// A channel is open; another is opened only once it has ended.
    ChannelOpen,
    /// No channel is open; nothing was sent.
    NoChannel,
    /// An earlier channel met a host key other than the enrolled one; the transport opens
    /// nothing more.
    HostKeyRejected {
        host: RemoteHostId,
        enrolled: HostKeyFingerprint,
    },
    /// The identity file is missing or not owner-only.
    IdentityFile { refusal: IdentityFileRefusal },
    /// The adapter has no enrolled identity yet.
    NotEnrolled,
    /// The management identity is for another host than the run's.
    WrongHost {
        run: RemoteHostId,
        other: RemoteHostId,
    },
    /// The agent's context does not belong to this run's kind.
    ContextForAnotherKind { context: ExecutionContext },
    /// The agent's invocation could not be rendered.
    Render { refusal: SshRenderRefusal },
    /// The operating system's random source failed; no key was made.
    KeyUnavailable,
    /// The key or the host's first frame could not be framed.
    Encoding,
    /// V12 refused the key or the host's first frame.
    Session { refusal: ControlRefusal },
    /// The client could not be started. When V12 had already taken the session, it was
    /// marked lost.
    Client { refusal: SshClientRefusal },
    /// V12 refused the session; nothing was started. Boxed: V12's refusal takes over 200
    /// bytes.
    Connect { refusal: Box<AdapterRefusal> },
    /// The session ended; see [`ControlEnd`].
    Ended { end: Box<ControlEnd> },
}

impl fmt::Display for ControlTransportRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelOpen => f.write_str("a control channel is already open"),
            Self::NoChannel => f.write_str("no control channel is open"),
            Self::HostKeyRejected { .. } => f.write_str(
                "an earlier control channel met a host key other than the enrolled one, so \
                 this transport opens nothing more",
            ),
            Self::IdentityFile { refusal } => write!(f, "{refusal}"),
            Self::NotEnrolled => f.write_str("the remote run has no enrolled host yet"),
            Self::WrongHost { .. } => {
                f.write_str("the management identity is for another host than the remote run's")
            }
            Self::ContextForAnotherKind { .. } => {
                f.write_str("the control agent runs in a context foreign to this remote run")
            }
            Self::Render { refusal } => write!(f, "{refusal}"),
            Self::KeyUnavailable => {
                f.write_str("the operating system's random source could not make a session key")
            }
            Self::Encoding => {
                f.write_str("the session key or the host's first control frame could not be framed")
            }
            Self::Session { refusal } => write!(f, "{refusal}"),
            Self::Client { refusal } => write!(f, "{refusal}"),
            Self::Connect { refusal } => write!(f, "{refusal}"),
            Self::Ended { end } => write!(f, "the control session ended: {}", end.reason),
        }
    }
}

impl std::error::Error for ControlTransportRefusal {}

/// The control session's transport for one remote run; see the module notes. It holds
/// at most one channel at a time.
#[derive(Debug)]
pub struct ControlTransport<'a> {
    program: PathBuf,
    working_directory: PathBuf,
    known_hosts: KnownHostsFile,
    identity_file: IdentityFile,
    limits: ControlLimits,
    invocation: &'a ControlInvocation,
    live: Option<ControlChannel<'a>>,
    rejected: Option<RejectedHostKey>,
}

impl<'a> ControlTransport<'a> {
    /// A transport that runs the client at `program` in `working_directory`, checked as
    /// [`ProcessSshPort::new`](super::ProcessSshPort::new) checks them, rendering
    /// `invocation` with `known_hosts`, `identity_file` and `limits` for every channel.
    pub fn new(
        program: impl Into<PathBuf>,
        working_directory: impl Into<PathBuf>,
        known_hosts: KnownHostsFile,
        identity_file: IdentityFile,
        limits: ControlLimits,
        invocation: &'a ControlInvocation,
    ) -> Result<Self, SshClientRefusal> {
        let program = program.into();
        check_program(&program)?;
        let working_directory = working_directory.into();
        check_working_directory(&working_directory)?;
        Ok(Self {
            program,
            working_directory,
            known_hosts,
            identity_file,
            limits,
            invocation,
            live: None,
            rejected: None,
        })
    }

    /// The client program, as configured.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The directory the client runs in, checked before every start.
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    pub fn limits(&self) -> ControlLimits {
        self.limits
    }

    /// The host key that closed this transport, if one did.
    pub fn rejected(&self) -> Option<&RejectedHostKey> {
        self.rejected.as_ref()
    }

    /// The open channel, if any.
    pub fn channel(&self) -> Option<&ControlChannel<'a>> {
        self.live.as_ref()
    }

    /// Opens a control session for the run `adapter` manages, in the steps of the
    /// module notes, and returns what V12 made of the remote's first frame.
    pub fn open<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        identity: &ManagementIdentity,
    ) -> Result<FrameOutcome, ControlTransportRefusal> {
        if self.live.is_some() {
            return Err(ControlTransportRefusal::ChannelOpen);
        }
        if let Some(rejected) = &self.rejected {
            return Err(ControlTransportRefusal::HostKeyRejected {
                host: rejected.host,
                enrolled: rejected.enrolled,
            });
        }
        check_identity_file(self.identity_file.path())
            .map_err(|refusal| ControlTransportRefusal::IdentityFile { refusal })?;
        let run = adapter
            .identity()
            .ok_or(ControlTransportRefusal::NotEnrolled)?
            .clone();
        if identity.host() != run.host {
            return Err(ControlTransportRefusal::WrongHost {
                run: run.host,
                other: identity.host(),
            });
        }
        let invocation: &'a ControlInvocation = self.invocation;
        let context = invocation.invocation.context();
        if !context_fits(context, adapter.selection().is_vm_sandbox()) {
            return Err(ControlTransportRefusal::ContextForAnotherKind { context });
        }
        let rendered = render_invocation(
            identity,
            known,
            &self.known_hosts,
            &self.identity_file,
            self.limits.ssh(),
            &invocation.invocation,
        )
        .map_err(|refusal| ControlTransportRefusal::Render { refusal })?;

        let random = SystemRandom::new();
        let mut key = PayloadCopy(vec![0; CONTROL_KEY_BYTES]);
        let mut nonce = [0u8; SESSION_NONCE_BYTES];
        random
            .fill(&mut key.0)
            .and_then(|()| random.fill(&mut nonce))
            .map_err(|_| ControlTransportRefusal::KeyUnavailable)?;
        let session = ControlSessionId::new(
            DigestBuilder::new(CONTROL_SESSION_DOMAIN)
                .bytes(&nonce)
                .finish(),
        );
        let binding = DigestBuilder::new(CONTROL_BINDING_DOMAIN)
            .digest(session.digest())
            .bytes(&key.0)
            .finish();
        let key_message =
            framed(&key.0, MAX_CONTROL_FRAME_BYTES).ok_or(ControlTransportRefusal::Encoding)?;
        let control_key = ControlKey::new(key.0.clone())
            .map_err(|refusal| ControlTransportRefusal::Session { refusal })?;
        drop(key);
        let mut control = ControlSession::open(run, session, binding, control_key, authority.now());
        let hello = control
            .seal_outbound(ControlBody::Heartbeat)
            .map_err(|refusal| ControlTransportRefusal::Session { refusal })?;
        let hello = encode(&hello).map_err(|_| ControlTransportRefusal::Encoding)?;

        check_working_directory(&self.working_directory)
            .map_err(|refusal| ControlTransportRefusal::Client { refusal })?;
        adapter
            .connect(known, self.known_hosts.key().host_key(), control, authority)
            .map_err(|refusal| ControlTransportRefusal::Connect {
                refusal: Box::new(refusal),
            })?;
        match ControlChannel::start(
            &self.program,
            &self.working_directory,
            session,
            rendered,
            self.limits,
            key_message,
            hello,
        ) {
            Ok(channel) => self.live = Some(channel),
            Err(refusal) => {
                if adapter.control().map(ControlSession::id) == Some(session) {
                    adapter.connection_lost();
                }
                return Err(ControlTransportRefusal::Client { refusal });
            }
        }
        // The receive ends the session at the silence deadline, so this loop ends.
        loop {
            let within = self.limits.max_silence();
            if let Some(outcome) = self.receive(adapter, authority, known, within)? {
                return Ok(outcome);
            }
        }
    }

    /// Delegates authority through V12 ([`RemoteVmAdapter::launch`]) and sends the first
    /// grant. A refusal ends the session.
    pub fn launch<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        operation: OperationId,
        attestation: Option<&AttestationRecord>,
    ) -> Result<(), ControlTransportRefusal> {
        self.check_current(adapter, authority, known)?;
        match adapter.launch(authority, operation, attestation) {
            Ok(grant) => self.send(adapter, authority, known, &grant),
            Err(refusal) => Err(self.refused(adapter, authority, known, refusal)),
        }
    }

    /// Renews the delegation through V12 ([`RemoteVmAdapter::renew`]) and sends the
    /// grant. A refusal ends the session; V12 ends authority it no longer honours.
    pub fn renew<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
    ) -> Result<(), ControlTransportRefusal> {
        self.check_current(adapter, authority, known)?;
        match adapter.renew(authority) {
            Ok(grant) => self.send(adapter, authority, known, &grant),
            Err(refusal) => Err(self.refused(adapter, authority, known, refusal)),
        }
    }

    /// Waits at most `within` for the remote's next frame and hands it to V12
    /// ([`RemoteVmAdapter::handle_frame`]); a renewal V12 grants is sent at once. `None`
    /// when no frame arrived. A refusal, or the channel's end, ends the session.
    pub fn receive<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        within: Duration,
    ) -> Result<Option<FrameOutcome>, ControlTransportRefusal> {
        self.check_current(adapter, authority, known)?;
        let received = self
            .live
            .as_mut()
            .ok_or(ControlTransportRefusal::NoChannel)?
            .receive(within);
        // A different worker may have rejected this host while we were waiting.
        // Do not handle a queued renewal, or report a healthy quiet channel, then.
        self.check_current(adapter, authority, known)?;
        let frame = match received {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(None),
            Err(reason) => return Err(self.end(adapter, authority, known, reason)),
        };
        match adapter.handle_frame(&frame, authority) {
            Ok(FrameOutcome::Renewed { grant }) => {
                self.send(adapter, authority, known, &grant)?;
                Ok(Some(FrameOutcome::Renewed { grant }))
            }
            Ok(outcome) => Ok(Some(outcome)),
            Err(refusal) => Err(self.refused(adapter, authority, known, refusal)),
        }
    }

    /// Closes the open channel, if any: stdin is closed, the client given time to end
    /// and then killed, and V12's session marked lost.
    pub fn close<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
    ) -> Option<ControlEnd> {
        self.finish(adapter, authority, known, ControlEndReason::Closed)
    }

    fn send<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        frame: &SealedFrame,
    ) -> Result<(), ControlTransportRefusal> {
        self.check_current(adapter, authority, known)?;
        let Some(channel) = self.live.as_mut() else {
            return Err(ControlTransportRefusal::NoChannel);
        };
        channel
            .send(frame)
            .map_err(|reason| self.end(adapter, authority, known, reason))
    }

    /// An authenticated socket does not outlive the shared enrollment that
    /// authorized it. Recheck before work, around reads and before any grant write.
    fn check_current<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
    ) -> Result<(), ControlTransportRefusal> {
        if self.live.is_none() {
            return Err(ControlTransportRefusal::NoChannel);
        }
        let current = adapter.identity().is_some_and(|identity| {
            known
                .enrollment(&identity.host)
                .is_some_and(|enrollment| &RemoteIdentity::from_enrollment(enrollment) == identity)
        });
        if !current {
            // Release the actual lease before a slow SSH close. Do not manufacture
            // a second mismatch observation; preserve the original shared record.
            let _ = adapter.begin_termination(authority);
            return Err(self.refused(adapter, authority, known, AdapterRefusal::StaleIdentity));
        }
        Ok(())
    }

    fn refused<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        refusal: AdapterRefusal,
    ) -> ControlTransportRefusal {
        let reason = ControlEndReason::Refused {
            refusal: Box::new(refusal),
        };
        self.end(adapter, authority, known, reason)
    }

    fn end<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        reason: ControlEndReason,
    ) -> ControlTransportRefusal {
        self.finish(adapter, authority, known, reason)
            .map_or(ControlTransportRefusal::NoChannel, |end| {
                ControlTransportRefusal::Ended { end: Box::new(end) }
            })
    }

    /// Ends the open channel for `reason`, reports a host-key mismatch the client
    /// reported, and marks V12's session lost while it is still this channel's.
    fn finish<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        reason: ControlEndReason,
    ) -> Option<ControlEnd> {
        let channel = self.live.take()?;
        let session = channel.session();
        let closed = channel.close(&reason);
        let host_key = match &closed.outcome {
            SshOutcome::HostKeyMismatch {
                host,
                enrolled,
                evidence,
            } => {
                // The adapter ends authority even when the rejection cannot be recorded.
                let _ = adapter.report_host_key_mismatch(
                    known,
                    authority,
                    rejection_evidence(evidence),
                );
                let rejected = RejectedHostKey {
                    host: *host,
                    enrolled: *enrolled,
                    evidence: evidence.clone(),
                };
                self.rejected = Some(rejected.clone());
                Some(rejected)
            }
            _ => None,
        };
        if adapter.control().map(ControlSession::id) == Some(session) {
            adapter.connection_lost();
        }
        Some(ControlEnd {
            session,
            reason,
            termination: closed.output.termination,
            stderr: closed.output.stderr,
            outcome: closed.outcome,
            host_key,
            ended_at: authority.now(),
        })
    }
}
