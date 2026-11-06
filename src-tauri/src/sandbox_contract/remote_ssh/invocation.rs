//! The OpenSSH client argv for one V12 management invocation (VM-W41: "command arguments
//! cannot become shell programs"; VM part §4.5: no secret copies in command arguments;
//! VM part §6.2: bounded calls).
//!
//! [`render_invocation`] checks the V12 decisions once more (the identity is current and
//! permits the action on the context's host, the host-key file is for that host's current
//! enrollment, the identity file is the identity's client key) and renders:
//!
//! ```text
//! ssh -F none
//!     -o UserKnownHostsFile=<rendered file> -o GlobalKnownHostsFile=none
//!     -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=<enrolled algorithm>
//!     -o UpdateHostKeys=no -o CheckHostIP=no -o VerifyHostKeyDNS=no
//!     -o BatchMode=yes -o PreferredAuthentications=publickey
//!     -o IdentitiesOnly=yes -o IdentityAgent=none -i <identity file>
//!     -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes
//!     -o PermitLocalCommand=no -o ProxyCommand=none -o ProxyJump=none
//!     -o ControlMaster=no -o ControlPath=none -o RequestTTY=no -o EscapeChar=none
//!     -o ConnectTimeout=<s> -o ServerAliveInterval=<s> -o ServerAliveCountMax=<n>
//!     -p <port> -l <account> -- <host> <encoded command>
//! ```
//!
//! Every value is typed before it gets here (V02 host and port, V12 account name and
//! encoded command, [`SshFilePath`]), so no value can split, start an option or expand.
//! The encoded command is one argv word after `--` and the host, so `ssh` passes it to the
//! remote shell unchanged. The invocation's stdin payload goes to the port as stdin only;
//! the renderer refuses an argv in which it appears in any encoding V07's scanner knows,
//! and the invocation carries no environment at all.

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::known_hosts::{KnownHostsFile, KnownHostsRefusal, SshTarget};
use super::outcome::{classify, SshOutcome, SshOutput, SshPort};
use super::path::SshFilePath;
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::provider::find_encoded;
use crate::sandbox_contract::remote::{
    ExecutionContext, HostKeyFingerprint, KnownHosts, ManagementAction, ManagementIdentity,
    ManagementRefusal, RemoteAccountName, RemoteHostId, RemoteInvocation, StdinPayload,
};

/// The OpenSSH client program; the port decides where its binary lives.
pub const SSH_PROGRAM: &str = "ssh";
/// The longest `ConnectTimeout` or `ServerAliveInterval` accepted, in seconds.
pub const MAX_TIMEOUT_SECONDS: u32 = 3_600;
/// The largest `ServerAliveCountMax` accepted.
pub const MAX_SERVER_ALIVE_COUNT: u32 = 100;
/// The longest deadline accepted for one invocation.
pub const MAX_DEADLINE: Duration = Duration::from_secs(24 * 3_600);
/// The largest output bound accepted, per stream.
pub const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

/// One typed limit of [`SshLimits`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SshLimit {
    ConnectTimeout,
    ServerAliveInterval,
    ServerAliveCountMax,
    Deadline,
    MaxStdout,
    MaxStderr,
}

/// Why limits were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum SshLimitsRefusal {
    /// The value is outside `min..=max`, in seconds for times and bytes for output.
    OutOfRange { limit: SshLimit, min: u64, max: u64 },
    /// The deadline would stop the client before its own connect timeout.
    DeadlineBeforeConnectTimeout,
}

impl fmt::Display for SshLimitsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { limit, min, max } => {
                write!(f, "{limit:?} must be between {min} and {max}")
            }
            Self::DeadlineBeforeConnectTimeout => {
                f.write_str("the deadline must be at least the connect timeout")
            }
        }
    }
}

impl std::error::Error for SshLimitsRefusal {}

/// The client's time and output limits: `ConnectTimeout`, `ServerAliveInterval` and
/// `ServerAliveCountMax` go into the argv; the deadline and output bounds bind the port
/// and the classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SshLimits {
    connect_timeout_seconds: u32,
    server_alive_interval_seconds: u32,
    server_alive_count_max: u32,
    deadline: Duration,
    max_stdout_bytes: u64,
    max_stderr_bytes: u64,
}

fn in_range(limit: SshLimit, value: u64, min: u64, max: u64) -> Result<(), SshLimitsRefusal> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(SshLimitsRefusal::OutOfRange { limit, min, max })
    }
}

impl SshLimits {
    /// The limits `runtime/guest_ssh.rs` uses today: a 10 s connect timeout, a keepalive
    /// every 10 s with 2 missed answers allowed, 120 s per command and 256 KiB per stream.
    pub const STANDARD: Self = Self {
        connect_timeout_seconds: 10,
        server_alive_interval_seconds: 10,
        server_alive_count_max: 2,
        deadline: Duration::from_secs(120),
        max_stdout_bytes: 256 * 1024,
        max_stderr_bytes: 256 * 1024,
    };

    /// Checks every limit against its range: times 1 s to [`MAX_TIMEOUT_SECONDS`], the
    /// keepalive count 1 to [`MAX_SERVER_ALIVE_COUNT`], the deadline 1 s to
    /// [`MAX_DEADLINE`] and not shorter than the connect timeout, output 1 byte to
    /// [`MAX_OUTPUT_BYTES`] per stream.
    pub fn new(
        connect_timeout_seconds: u32,
        server_alive_interval_seconds: u32,
        server_alive_count_max: u32,
        deadline: Duration,
        max_stdout_bytes: u64,
        max_stderr_bytes: u64,
    ) -> Result<Self, SshLimitsRefusal> {
        let max_seconds = u64::from(MAX_TIMEOUT_SECONDS);
        in_range(
            SshLimit::ConnectTimeout,
            u64::from(connect_timeout_seconds),
            1,
            max_seconds,
        )?;
        in_range(
            SshLimit::ServerAliveInterval,
            u64::from(server_alive_interval_seconds),
            1,
            max_seconds,
        )?;
        in_range(
            SshLimit::ServerAliveCountMax,
            u64::from(server_alive_count_max),
            1,
            u64::from(MAX_SERVER_ALIVE_COUNT),
        )?;
        if deadline < Duration::from_secs(1) || deadline > MAX_DEADLINE {
            return Err(SshLimitsRefusal::OutOfRange {
                limit: SshLimit::Deadline,
                min: 1,
                max: MAX_DEADLINE.as_secs(),
            });
        }
        if deadline < Duration::from_secs(u64::from(connect_timeout_seconds)) {
            return Err(SshLimitsRefusal::DeadlineBeforeConnectTimeout);
        }
        in_range(SshLimit::MaxStdout, max_stdout_bytes, 1, MAX_OUTPUT_BYTES)?;
        in_range(SshLimit::MaxStderr, max_stderr_bytes, 1, MAX_OUTPUT_BYTES)?;
        Ok(Self {
            connect_timeout_seconds,
            server_alive_interval_seconds,
            server_alive_count_max,
            deadline,
            max_stdout_bytes,
            max_stderr_bytes,
        })
    }

    pub fn connect_timeout_seconds(&self) -> u32 {
        self.connect_timeout_seconds
    }

    pub fn server_alive_interval_seconds(&self) -> u32 {
        self.server_alive_interval_seconds
    }

    pub fn server_alive_count_max(&self) -> u32 {
        self.server_alive_count_max
    }

    /// When the port stops the client.
    pub fn deadline(&self) -> Duration {
        self.deadline
    }

    /// The most stdout accepted; the port reads at most one byte more.
    pub fn max_stdout_bytes(&self) -> u64 {
        self.max_stdout_bytes
    }

    /// The most stderr accepted; the port reads at most one byte more.
    pub fn max_stderr_bytes(&self) -> u64 {
        self.max_stderr_bytes
    }
}

/// The private key file of the management identity's client key. Sources include:
/// [`generate_management_key`](super::generate_management_key), which also restricts the
/// file to its owner ([`protect_identity_file`](super::protect_identity_file)), or the
/// home vault or an explicitly selected owner file. This value alone proves no vault
/// grant. [`ManagementChannel`](super::ManagementChannel) checks the protection before
/// every call. Removing the file, rotating the key and the vault's grant for it are not
/// here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityFile {
    credential: CredentialRef,
    path: SshFilePath,
}

impl IdentityFile {
    /// The file at `path` holding the key named by this opaque credential handle.
    pub fn new(credential: CredentialRef, path: SshFilePath) -> Self {
        Self { credential, path }
    }

    pub fn credential(&self) -> CredentialRef {
        self.credential
    }

    pub fn path(&self) -> &SshFilePath {
        &self.path
    }
}

/// Why an invocation was not rendered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SshRenderRefusal {
    /// V12 refused the management identity: stale, not permitted, or another host.
    Management { refusal: ManagementRefusal },
    /// The host-key file is for another host than the identity's.
    KnownHostsForAnotherHost {
        identity: RemoteHostId,
        file: RemoteHostId,
    },
    /// The host-key file's key is no longer the host's current enrollment.
    KnownHosts { refusal: KnownHostsRefusal },
    /// The identity file holds another key than the identity's client key.
    IdentityFileForAnotherKey,
    /// The stdin payload appears in the argv; it goes over stdin only.
    SecretInArgv,
}

impl fmt::Display for SshRenderRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Management { refusal } => write!(f, "{refusal}"),
            Self::KnownHostsForAnotherHost { .. } => {
                f.write_str("the known_hosts file is for another host than the identity's")
            }
            Self::KnownHosts { refusal } => write!(f, "{refusal}"),
            Self::IdentityFileForAnotherKey => f.write_str(
                "the identity file holds another key than the management identity's client key",
            ),
            Self::SecretInArgv => f.write_str(
                "the stdin payload appears in the ssh arguments; secrets go over stdin only",
            ),
        }
    }
}

impl std::error::Error for SshRenderRefusal {}

impl From<ManagementRefusal> for SshRenderRefusal {
    fn from(refusal: ManagementRefusal) -> Self {
        Self::Management { refusal }
    }
}

/// One rendered `ssh` invocation: the argv, the stdin of the V12 invocation it was
/// rendered from, and what classification needs. It cannot be built from strings, and
/// `Debug` shows the stdin length only.
#[derive(Debug)]
pub struct SshInvocation<'a> {
    argv: Vec<String>,
    target: SshTarget,
    account: RemoteAccountName,
    enrolled: HostKeyFingerprint,
    identity_file: SshFilePath,
    limits: SshLimits,
    invocation: &'a RemoteInvocation,
}

impl<'a> SshInvocation<'a> {
    /// The full argv, [`SSH_PROGRAM`] first.
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// The arguments after the program name.
    pub fn arguments(&self) -> &[String] {
        self.argv.get(1..).unwrap_or_default()
    }

    /// What the port writes to the client's stdin before closing it.
    pub fn stdin(&self) -> Option<&'a StdinPayload> {
        self.invocation.stdin()
    }

    pub fn limits(&self) -> SshLimits {
        self.limits
    }

    pub fn target(&self) -> &SshTarget {
        &self.target
    }

    pub fn account(&self) -> &RemoteAccountName {
        &self.account
    }

    /// The fingerprint of the key the host must present.
    pub fn enrolled(&self) -> HostKeyFingerprint {
        self.enrolled
    }

    pub fn identity_file(&self) -> &SshFilePath {
        &self.identity_file
    }

    pub fn action(&self) -> ManagementAction {
        self.invocation.action()
    }

    pub fn context(&self) -> ExecutionContext {
        self.invocation.context()
    }

    /// Hands the invocation to `port` and classifies what it reports.
    pub fn run(&self, port: &mut dyn SshPort) -> SshRun {
        let output = port.run(self);
        SshRun {
            outcome: classify(self, &output),
            output,
        }
    }
}

/// What one run reported and how it was classified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshRun {
    pub outcome: SshOutcome,
    pub output: SshOutput,
}

fn push_option(argv: &mut Vec<String>, name: &str, value: impl fmt::Display) {
    argv.push("-o".to_owned());
    argv.push(format!("{name}={value}"));
}

/// Renders the `ssh` argv for `invocation`; see the module notes for the exact form.
///
/// Refused: an identity that is stale or does not permit the action, a context on
/// another host, a host-key file for another host or for a key that is no longer the
/// host's current enrollment, an identity file for another client key, and an argv
/// containing the stdin payload.
pub fn render_invocation<'a>(
    identity: &ManagementIdentity,
    known: &KnownHosts,
    known_hosts: &KnownHostsFile,
    identity_file: &IdentityFile,
    limits: SshLimits,
    invocation: &'a RemoteInvocation,
) -> Result<SshInvocation<'a>, SshRenderRefusal> {
    identity.check_current(known)?;
    identity.permits(invocation.action())?;
    if invocation.context().host() != identity.host() {
        return Err(ManagementRefusal::WrongHost {
            identity: identity.host(),
            context: invocation.context().host(),
        }
        .into());
    }
    let key = known_hosts.key();
    let target = key.target();
    if target.host() != identity.host() {
        return Err(SshRenderRefusal::KnownHostsForAnotherHost {
            identity: identity.host(),
            file: target.host(),
        });
    }
    key.check_current(known)
        .map_err(|refusal| SshRenderRefusal::KnownHosts { refusal })?;
    if identity_file.credential() != identity.client_key() {
        return Err(SshRenderRefusal::IdentityFileForAnotherKey);
    }

    let mut argv = vec![SSH_PROGRAM.to_owned(), "-F".to_owned(), "none".to_owned()];
    push_option(&mut argv, "UserKnownHostsFile", known_hosts.path());
    push_option(&mut argv, "GlobalKnownHostsFile", "none");
    push_option(&mut argv, "StrictHostKeyChecking", "yes");
    push_option(&mut argv, "HostKeyAlgorithms", key.algorithm().tag());
    push_option(&mut argv, "UpdateHostKeys", "no");
    push_option(&mut argv, "CheckHostIP", "no");
    push_option(&mut argv, "VerifyHostKeyDNS", "no");
    push_option(&mut argv, "BatchMode", "yes");
    push_option(&mut argv, "PreferredAuthentications", "publickey");
    push_option(&mut argv, "IdentitiesOnly", "yes");
    push_option(&mut argv, "IdentityAgent", "none");
    argv.push("-i".to_owned());
    argv.push(identity_file.path().as_str().to_owned());
    push_option(&mut argv, "ForwardAgent", "no");
    push_option(&mut argv, "ForwardX11", "no");
    push_option(&mut argv, "ClearAllForwardings", "yes");
    push_option(&mut argv, "PermitLocalCommand", "no");
    push_option(&mut argv, "ProxyCommand", "none");
    push_option(&mut argv, "ProxyJump", "none");
    push_option(&mut argv, "ControlMaster", "no");
    push_option(&mut argv, "ControlPath", "none");
    push_option(&mut argv, "RequestTTY", "no");
    push_option(&mut argv, "EscapeChar", "none");
    push_option(&mut argv, "ConnectTimeout", limits.connect_timeout_seconds);
    push_option(
        &mut argv,
        "ServerAliveInterval",
        limits.server_alive_interval_seconds,
    );
    push_option(
        &mut argv,
        "ServerAliveCountMax",
        limits.server_alive_count_max,
    );
    argv.push("-p".to_owned());
    argv.push(target.port().to_string());
    argv.push("-l".to_owned());
    argv.push(identity.account().as_str().to_owned());
    argv.push("--".to_owned());
    argv.push(target.command_host());
    argv.push(invocation.command().as_str().to_owned());

    if let Some(stdin) = invocation.stdin() {
        let payload = stdin.expose_to_transport();
        let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
        let payload = payload.strip_suffix(b"\r").unwrap_or(payload);
        if argv
            .iter()
            .any(|word| find_encoded(word.as_bytes(), payload).is_some())
        {
            return Err(SshRenderRefusal::SecretInArgv);
        }
    }

    Ok(SshInvocation {
        argv,
        target: target.clone(),
        account: identity.account().clone(),
        enrolled: key.enrollment().fingerprint,
        identity_file: identity_file.path().clone(),
        limits,
        invocation,
    })
}
