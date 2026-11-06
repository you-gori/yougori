//! Test doubles (tests only): wire-form key blobs, an enrolled host with a management
//! identity, scratch paths on the harness's temporary directory, and a fake SSH port
//! that checks the argv it is handed. Nothing here runs `ssh` or opens a socket.

use std::collections::BTreeSet;

use super::invocation::{IdentityFile, SshInvocation};
use super::known_hosts::{EnrolledHostKey, KnownHostsFile, SshTarget};
use super::outcome::{SshOutput, SshPort, SshTermination};
use super::path::SshFilePath;
use crate::foundation::evidence::ProviderKind;
use crate::foundation::ids::{digest, MonotonicTime};
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::destinations::{Authority, DestinationPort};
use crate::sandbox_contract::remote::{
    EnrollmentEvidence, EnrollmentPolicy, ExecutionContext, HostEnrollment, HostKey,
    HostKeyAlgorithm, KnownHosts, ManagementAction, ManagementIdentity, OptionTerminator,
    ProgramPath, RegionName, RemoteAccountName, RemoteCommand, RemoteHostId, RemoteInvocation,
    RemoteShellKind,
};

/// GitHub's published Ed25519 host key and its published SHA256 fingerprint: a
/// known-answer pair for the base64 and fingerprint code.
pub const PUBLISHED_ED25519: &str =
    "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
pub const PUBLISHED_ED25519_SHA256: &str = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU";

pub fn ssh_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

pub fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

pub fn ed25519_blob(seed: u8) -> Vec<u8> {
    concat(&[ssh_string(b"ssh-ed25519"), ssh_string(&[seed; 32])])
}

pub fn ecdsa_blob(algorithm: HostKeyAlgorithm, seed: u8) -> Vec<u8> {
    let (name, curve, coordinate) = match algorithm {
        HostKeyAlgorithm::EcdsaNistp256 => ("ecdsa-sha2-nistp256", "nistp256", 32),
        HostKeyAlgorithm::EcdsaNistp384 => ("ecdsa-sha2-nistp384", "nistp384", 48),
        other => panic!("not ECDSA: {other:?}"),
    };
    let mut point = vec![0x04];
    point.extend(std::iter::repeat_n(seed, 2 * coordinate));
    concat(&[
        ssh_string(name.as_bytes()),
        ssh_string(curve.as_bytes()),
        ssh_string(&point),
    ])
}

/// An RSA blob with exponent 65537 and a modulus of `bits` bits (a multiple of 8).
pub fn rsa_blob(bits: usize, seed: u8) -> Vec<u8> {
    let mut modulus = vec![0x00, 0x80 | seed];
    modulus.extend(std::iter::repeat_n(seed | 1, bits / 8 - 1));
    concat(&[
        ssh_string(b"ssh-rsa"),
        ssh_string(&[0x01, 0x00, 0x01]),
        ssh_string(&modulus),
    ])
}

pub fn blob_for(algorithm: HostKeyAlgorithm, seed: u8) -> Vec<u8> {
    match algorithm {
        HostKeyAlgorithm::Ed25519 => ed25519_blob(seed),
        HostKeyAlgorithm::EcdsaNistp256 | HostKeyAlgorithm::EcdsaNistp384 => {
            ecdsa_blob(algorithm, seed)
        }
        HostKeyAlgorithm::RsaSha2_512 => rsa_blob(2_048, seed),
    }
}

pub fn host_id(number: u8) -> RemoteHostId {
    RemoteHostId::of(
        ProviderKind::Crusoe,
        &RegionName::new("us-east-1").unwrap(),
        &digest("yougori/test/instance/v1", &[&[number]]),
    )
}

pub fn mgmt_key() -> CredentialRef {
    CredentialRef::from_digest(digest("yougori/test/ssh-client-key/v1", &[b"mgmt"]))
}

pub fn other_key() -> CredentialRef {
    CredentialRef::from_digest(digest("yougori/test/ssh-client-key/v1", &[b"other"]))
}

/// `text` through V02's authority parser, port 22 when none is written.
pub fn authority(text: &str) -> Authority {
    Authority::parse(text, DestinationPort::new(22).unwrap()).unwrap()
}

pub fn helper() -> ProgramPath {
    ProgramPath::new("/opt/yougori/bin/yougori-remote").unwrap()
}

pub fn launch_command() -> RemoteCommand {
    RemoteCommand::new(helper(), OptionTerminator::DoubleDash)
        .flag("--launch-vm")
        .unwrap()
        .operand("vm one; $(id)")
        .unwrap()
}

/// One enrolled host with its key, target and a management identity.
pub struct World {
    pub known: KnownHosts,
    pub enrollment: HostEnrollment,
    pub identity: ManagementIdentity,
    pub key: EnrolledHostKey,
}

impl World {
    /// Host 1 at `address`, enrolled through the provider API with `blob`.
    pub fn new(address: &str, algorithm: HostKeyAlgorithm, blob: Vec<u8>) -> Self {
        let mut known = KnownHosts::new();
        let host_key = HostKey::new(algorithm, blob.clone()).unwrap();
        let enrollment = known
            .enroll(
                host_id(1),
                &host_key,
                EnrollmentEvidence::ProviderApi {
                    reported: host_key.fingerprint(),
                },
                EnrollmentPolicy::default(),
                MonotonicTime::ZERO,
            )
            .unwrap();
        let identity = identity_for(&enrollment, &ManagementAction::ALL);
        let target = SshTarget::new(host_id(1), authority(address));
        let key = EnrolledHostKey::new(&known, target, algorithm, blob).unwrap();
        Self {
            known,
            enrollment,
            identity,
            key,
        }
    }

    /// The usual fixture: an Ed25519 host at 203.0.113.7, port 2222.
    pub fn standard() -> Self {
        Self::new(
            "203.0.113.7:2222",
            HostKeyAlgorithm::Ed25519,
            ed25519_blob(1),
        )
    }

    pub fn shell(&self) -> ExecutionContext {
        ExecutionContext::RemoteHostShell { host: host_id(1) }
    }

    pub fn launch(&self) -> RemoteInvocation {
        RemoteInvocation::new(
            &self.identity,
            &self.known,
            ManagementAction::LaunchVm,
            self.shell(),
            &launch_command(),
        )
        .unwrap()
    }
}

pub fn identity_for(
    enrollment: &HostEnrollment,
    actions: &[ManagementAction],
) -> ManagementIdentity {
    ManagementIdentity::new(
        enrollment,
        RemoteAccountName::new("yougori").unwrap(),
        mgmt_key(),
        RemoteShellKind::Posix,
        actions.iter().copied().collect::<BTreeSet<_>>(),
    )
    .unwrap()
}

/// A scratch directory under the harness's temporary directory, as an OpenSSH path.
pub struct Scratch {
    _directory: tempfile::TempDir,
    base: String,
}

impl Scratch {
    pub fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("remote-ssh-")
            .tempdir()
            .unwrap();
        let base = directory.path().to_str().unwrap().replace('\\', "/");
        Self {
            _directory: directory,
            base,
        }
    }

    pub fn path(&self, name: &str) -> SshFilePath {
        SshFilePath::new(format!("{}/{name}", self.base)).unwrap()
    }
}

/// A written `known_hosts` file and an identity file for `world`.
pub fn files(world: &World, scratch: &Scratch) -> (KnownHostsFile, IdentityFile) {
    let known_hosts =
        KnownHostsFile::write(world.key.clone(), scratch.path("known_hosts")).unwrap();
    let identity_file = IdentityFile::new(mgmt_key(), scratch.path("id_ed25519"));
    (known_hosts, identity_file)
}

pub fn exited(code: i32, stderr: &str) -> SshOutput {
    SshOutput {
        termination: SshTermination::Exited { code },
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

/// A port that asserts it is handed exactly the expected argv, records the stdin, and
/// replies with a scripted output.
pub struct FakeSshPort {
    pub expected_argv: Vec<String>,
    pub reply: SshOutput,
    pub stdin_seen: Vec<Option<Vec<u8>>>,
}

impl FakeSshPort {
    pub fn new(expected_argv: Vec<String>, reply: SshOutput) -> Self {
        Self {
            expected_argv,
            reply,
            stdin_seen: Vec::new(),
        }
    }
}

impl SshPort for FakeSshPort {
    fn run(&mut self, invocation: &SshInvocation<'_>) -> SshOutput {
        assert_eq!(invocation.argv(), self.expected_argv.as_slice());
        self.stdin_seen.push(
            invocation
                .stdin()
                .map(|stdin| stdin.expose_to_transport().to_vec()),
        );
        self.reply.clone()
    }
}
