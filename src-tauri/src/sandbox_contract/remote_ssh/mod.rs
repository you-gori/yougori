//! M16A to M16G: the OpenSSH client adapter for V12's remote management, rendered, run
//! and parsed (VM-W41, slices of M16; docs/combined-gpu-memory-and-vm-sandbox-plan.md,
//! VM part §4.5, §6.2, §6.3, §7.6, VM-D14; VM-W41 acceptance "host-key changes rejected;
//! command arguments cannot become shell programs"; VM-CP-33 / VM-P42: nothing unproven
//! passes).
//!
//! V12 (`sandbox_contract::remote`) decides whom management trusts and what it runs: the
//! enrolled host key in [`KnownHosts`](crate::sandbox_contract::remote::KnownHosts), the
//! [`ManagementIdentity`](crate::sandbox_contract::remote::ManagementIdentity), and the
//! [`RemoteInvocation`](crate::sandbox_contract::remote::RemoteInvocation) with its
//! encoded command and stdin. This module turns those decisions into input for the stock
//! OpenSSH client and reads the client's result back. What is rendered and parsed:
//!
//! - `known_hosts`: [`SshTarget`] binds the enrolled host to its network authority (V02's
//!   canonical host and port). [`EnrolledHostKey`] is the host key in SSH wire form,
//!   accepted only while V12's `KnownHosts::verify` accepts it. [`KnownHostsFile::write`]
//!   writes the exact OpenSSH `known_hosts` line for it (`[host]:port` for a port other
//!   than 22, the enrolled algorithm and key only, one line, no wildcards, markers,
//!   hashing or comments) to a new file at a path the caller supplies, and
//!   [`parse_known_hosts`] reads that format back into the enrolled key, refusing
//!   anything it did not render; a file holding another key is refused with V12's
//!   `HostKeyRefusal::Changed`.
//! - `invocation`: [`render_invocation`] gives the exact `ssh` argv for one V12
//!   invocation: no configuration file (`-F none`), the rendered file as the only
//!   host-key source, strict checking, the enrolled algorithm only, no key updates, no
//!   agent, forwarding, local command, proxy, multiplexing or TTY, typed time limits
//!   ([`SshLimits`]), `-p`, `-l`, `--`, the host and V12's encoded command as the single
//!   remote command word. Secrets travel only as the invocation's stdin payload: the
//!   argv is refused if the payload appears in it, and the invocation has no
//!   environment. Paths are [`SshFilePath`]s, which nothing in OpenSSH can split or
//!   expand.
//! - `outcome`: the typed [`SshPort`] that runs the client, and [`classify`], which maps
//!   the exit status and stderr to an [`SshOutcome`]: remote exit code, host-key mismatch
//!   (ending delegation as V12's refusal does), authentication refused, connection
//!   failed, timeout, output over a bound, and `Uncertain` for anything unrecognised,
//!   never success.
//! - `process` (M16B): [`ProcessSshPort`], the port that runs the stock client from a
//!   configured absolute path (an `.exe` on a local drive on Windows), never through a
//!   shell, with exactly the rendered arguments, a cleared environment (`SystemRoot` and `ProgramData`
//!   on Windows), a dedicated working directory without an entry named `none`, the stdin
//!   payload written once and closed, both output streams read to one byte over their
//!   bounds, the client's end watched apart from its pipes, and the deadline kept by
//!   killing the client. It is not contained in PX1's job object; the `process` notes say
//!   why killing the client itself ends everything it started.
//! - `management` (M16C): [`ManagementChannel`], which runs management invocations for
//!   one run of V12's [`RemoteVmAdapter`](crate::sandbox_contract::remote::RemoteVmAdapter)
//!   only as the adapter's state allows. It covers the host, the enrollment and the context
//!   of the run's kind. Supervising and the Jupyter password run only within the host's
//!   current authority, so no call revives ended authority. A changed host key stops
//!   renewals and closes the channel. Typed probes turn runs into V12
//!   [`RemoteCapabilityEvidence`](crate::sandbox_contract::remote::RemoteCapabilityEvidence)
//!   in their own context, so a host shell never stands for a VM workload.
//! - `keygen` and `protection` (M16D): [`generate_management_key`] has the stock client's
//!   `ssh-keygen` write a new Ed25519 key (exactly `ssh-keygen -q -t ed25519 -N "" -C
//!   <comment> -f <path>`, to a path where nothing exists yet, through
//!   [`ProcessKeygenPort`] with the process port's checks and rules), makes the private key
//!   file owner-only ([`protect_identity_file`]: a protected DACL for the current user and
//!   SYSTEM on Windows, mode `0600` on Unix), reads the `.pub` line back strictly and
//!   derives the key's [`CredentialRef`](crate::foundation::transfer::CredentialRef) from
//!   its blob. The result is the [`IdentityFile`], the `authorized_keys` line and the
//!   OpenSSH fingerprint; the engine never reads the private key. [`ManagementChannel`]
//!   refuses every call while [`check_identity_file`] refuses its identity file.
//! - `control_channel` and `control_transport` (M16G, M16 (c3)): the transport of V12's
//!   control session. [`ControlTransport`] makes a fresh 32-byte session key per session
//!   from the operating system's CSPRNG and sends it as the first length-prefixed message
//!   on the stdin of a [`ControlChannel`], a long-lived run of the client under the
//!   process port's rules running the configured [`ControlAgent`]. No further key exchange
//!   is added: the SSH channel is already authenticated by the pinned host key and the
//!   management identity, and encrypted (the `control_transport` notes say what that
//!   relies on). Frames are V12's sealed frames in strict JSON, length-prefixed and
//!   bounded, both ways. V12's adapter judges every frame, and every end of the channel
//!   (end of stream, exit, broken pipe, silence, a refused or malformed frame) marks the
//!   session lost. A host-key mismatch the client reports reaches V12 as `management`
//!   reports it, and a reconnect is a new channel, key and session that V12 judges
//!   afresh, so it never revives ended authority.
//!
//! What runs now: rendering, the `known_hosts` file, starting and supervising the client
//! process, generating the management key and protecting its identity file, gating
//! management calls on the remote run, carrying the control session, and classifying
//! what the client reports. What does not, and lies outside this module: the remote
//! control agent (M16 (c1)) and the product wiring (M16 (c2)); the provider transport
//! that creates the host and reports its address and key (V12's `RemoteProviderPort`);
//! installing the public key at the provider (M16 (a)); a vault grant for the key, its
//! encryption at rest, rotation and removal; and choosing where the client and
//! `ssh-keygen` binaries live, which the caller configures. Nothing here opens a socket or
//! touches `~/.ssh` itself; the only I/O is writing and reading back the `known_hosts`
//! file at the caller's path, starting the client and `ssh-keygen` programs the caller
//! names, the client's pipes, reading the public key file back, and setting and reading
//! the identity file's DACL or mode. No test runs a real OpenSSH client or `ssh-keygen`:
//! the process tests start this test executable as a fake of either that records what it
//! was given, and the control tests start it as the client and the agent behind it.
//!
//! Relation to `runtime/guest_ssh.rs` (production code of another area, not used or
//! changed here). That code runs pinned-host-key SSH to full VMs through a loopback
//! forward with `-F none -T -a -x`, `BatchMode`, `StrictHostKeyChecking=yes`,
//! `UpdateHostKeys=no`, `ClearAllForwardings`, `IdentitiesOnly`, `ConnectTimeout=10`,
//! `ServerAliveInterval=10`, `ServerAliveCountMax=2`, `PermitLocalCommand=no`,
//! `GlobalKnownHostsFile=none`, a quoted `UserKnownHostsFile` holding an unparsed
//! host-key string, a 120 s deadline, 256 KiB output bounds and `String` errors. The
//! argv here keeps every one of those settings ([`SshLimits::STANDARD`] holds its
//! limits; `RequestTTY=no`, `ForwardAgent=no` and `ForwardX11=no` are the long forms of
//! `-T -a -x`) and adds: the enrolled algorithm pinned in `HostKeyAlgorithms`, a parsed
//! and re-verified key line written to a fresh file, `IdentityAgent=none`,
//! `ProxyCommand`/`ProxyJump=none`, `ControlMaster=no`/`ControlPath=none`,
//! `CheckHostIP=no`, `VerifyHostKeyDNS=no`, `PreferredAuthentications=publickey`, `--`
//! before the host, typed host, account and paths instead of quoting, the V12 identity,
//! enrollment and action checks, and typed classification.
//!
//! OpenSSH option names and values, checked from memory of the 8.x/9.x client (no client
//! is run here). Confident, present in every 8.x and 9.x release: `-F none`, `-i`, `-p`,
//! `-l`, `--`, `UserKnownHostsFile`, `StrictHostKeyChecking=yes`, `HostKeyAlgorithms`
//! (including `rsa-sha2-512`), `UpdateHostKeys=no`, `CheckHostIP=no`,
//! `VerifyHostKeyDNS=no`, `BatchMode=yes`, `PreferredAuthentications=publickey`,
//! `IdentitiesOnly=yes`, `IdentityAgent=none`, `ForwardAgent=no`, `ForwardX11=no`,
//! `ClearAllForwardings=yes`, `PermitLocalCommand=no`, `ProxyCommand=none`,
//! `ControlMaster=no`, `ControlPath=none`, `RequestTTY=no`, `EscapeChar=none` (no escape
//! sequences even if a later change requested a terminal), `ConnectTimeout`,
//! `ServerAliveInterval`, `ServerAliveCountMax`. Unsure:
//!
//! - `GlobalKnownHostsFile=none`: `none` is documented for `UserKnownHostsFile` (8.4+)
//!   but not for `GlobalKnownHostsFile`. A client that does not treat it specially opens
//!   a file literally named `none` relative to its working directory, so the port must
//!   start the client in a directory without one ([`ProcessSshPort`] checks it before
//!   every start); naming the rendered file again would avoid the question.
//! - `ProxyJump=none`: `none` support is version dependent, but `ProxyCommand=none`
//!   comes first and OpenSSH ignores a later `ProxyJump` once `ProxyCommand` is set.
//! - `KnownHostsCommand` (8.5+) is not passed, since older clients refuse the name; with
//!   `-F none` nothing sets it.
//! - With `CheckHostIP=yes` (the default before 8.5) the client would append an
//!   IP-address line to the known-hosts file; `CheckHostIP=no` prevents that, and a
//!   changed file is refused on read-back.
//! - The stderr messages [`classify`] recognises are listed in the `outcome` notes, with
//!   the limit that a remote command's own stderr can imitate them.
//! - The Windows client's environment needs `SystemRoot` and `ProgramData` on the
//!   tested installation; the latter's absence causes a silent exit 255. Actual
//!   cross-host acceptance uses this restricted environment. Other client versions
//!   and diagnostic wording remain separate compatibility evidence.
//!
//! Unit tests use fakes and local files. Real client/server/VM evidence is produced
//! separately by scripts/acceptance/remote-home.py and the remote receiver harnesses.

mod control_channel;
mod control_transport;
mod engine_client;
mod engine_protocol;
mod owner_key;

pub use engine_client::{confirmed_creation_cancelled, confirmed_remote_end, EngineManagement};
pub use engine_protocol::{RemoteManagementRequest, RemoteVmBinding, RemoteVmObservation};
pub use owner_key::{owner_identity_file, parse_owner_public_key, OwnerPublicKey};
mod invocation;
mod keygen;
mod known_hosts;
mod management;
mod outcome;
mod path;
mod process;
mod protection;
mod wire;

#[cfg(all(test, windows))]
mod fake_client;
#[cfg(all(test, windows))]
mod fake_keygen;
#[cfg(all(test, windows))]
mod fake_remote;
#[cfg(test)]
mod fakes;
#[cfg(all(test, windows))]
mod tests_control;
#[cfg(test)]
mod tests_invocation;
#[cfg(test)]
mod tests_keygen;
#[cfg(all(test, windows))]
mod tests_keygen_process;
#[cfg(test)]
mod tests_known_hosts;
#[cfg(test)]
mod tests_management;
#[cfg(test)]
mod tests_outcome;
#[cfg(test)]
mod tests_path;
#[cfg(all(test, windows))]
mod tests_process;
#[cfg(test)]
mod tests_protection;
#[cfg(test)]
mod tests_wire;

pub use control_channel::{
    ControlChannel, ControlEndReason, CONTROL_KEY_BYTES, MAX_CONTROL_FRAME_BYTES,
};
pub use control_transport::{
    ControlAgent, ControlEnd, ControlInvocation, ControlLimits, ControlLimitsRefusal,
    ControlTransport, ControlTransportRefusal, CONTROL_BINDING_DOMAIN, CONTROL_SESSION_DOMAIN,
    MAX_CONTROL_SILENCE, MAX_WRITE_WAIT,
};
pub use invocation::{
    render_invocation, IdentityFile, SshInvocation, SshLimit, SshLimits, SshLimitsRefusal,
    SshRenderRefusal, SshRun, MAX_DEADLINE, MAX_OUTPUT_BYTES, MAX_SERVER_ALIVE_COUNT,
    MAX_TIMEOUT_SECONDS, SSH_PROGRAM,
};
pub use keygen::{
    generate_management_key, GeneratedManagementKey, KeyComment, KeyCommentRefusal, KeyFile,
    KeygenInvocation, KeygenPort, KeygenRefusal, ManagementPublicKey, ProcessKeygenPort,
    PublicKeyProblem, MANAGEMENT_KEY_DOMAIN, MAX_KEY_COMMENT_BYTES, MAX_PUBLIC_KEY_BYTES,
    SSH_KEYGEN_PROGRAM,
};
pub use known_hosts::{
    parse_known_hosts, EnrolledHostKey, FileOperation, KnownHostsFile, KnownHostsProblem,
    KnownHostsRefusal, SshTarget, DEFAULT_SSH_PORT, MAX_KNOWN_HOSTS_BYTES,
};
pub use management::{
    ManagementCall, ManagementCallRefusal, ManagementChannel, ProbeResult, RejectedHostKey,
    KVM_DEVICE, TEST_PROGRAM,
};
pub use outcome::{
    classify, ConnectionFailure, HostKeyEvidence, OutputStream, PortFailure, SshOutcome, SshOutput,
    SshPort, SshTermination, TimeoutPhase, SSH_CLIENT_ERROR_STATUS,
};
pub use path::{SshFilePath, SshPathRefusal, MAX_SSH_PATH_BYTES};
pub use process::{
    ProcessSshPort, SshClientRefusal, CLIENT_ENVIRONMENT, NONE_ENTRY, OUTPUT_DRAIN_WAIT, REAP_WAIT,
};
pub use protection::{
    check_identity_file, protect_identity_file, IdentityFileRefusal, ProtectionStep,
    LOCAL_SYSTEM_SID, OWNER_ONLY_MODE,
};
pub use wire::{known_hosts_key_type, KeyBlobProblem, MIN_RSA_MODULUS_BITS};
