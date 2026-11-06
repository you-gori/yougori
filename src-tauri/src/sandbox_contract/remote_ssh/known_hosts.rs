//! The OpenSSH `known_hosts` file for one enrolled host, rendered and parsed back (VM-W41:
//! host-key changes rejected; VM part §7.6: identity through a supported enrollment flow).
//!
//! V12's [`KnownHosts`] holds one enrolled key per host, by fingerprint. The file written
//! here holds exactly that key and nothing else: one line, `<host> <key type> <base64>`,
//! with the host written as OpenSSH looks it up (`name` or address for port 22,
//! `[name]:port` otherwise, an IPv6 address without brackets on port 22 and inside them on
//! another), no wildcard, negation, host list, hashed host, comment or `@cert-authority` /
//! `@revoked` marker. [`parse_known_hosts`] accepts that format only: it re-renders what it
//! read and refuses the text unless the two are byte-equal, and the key must be one V12's
//! [`KnownHosts::verify`] accepts for the host, so a file holding another key is refused
//! with V12's own [`HostKeyRefusal::Changed`].
//!
//! The blob is the key in SSH wire form (RFC 4253 §6.6), the `K_S` an SSH server presents
//! and the bytes a `known_hosts` line encodes. This adapter takes those bytes as V12's
//! [`HostKey`] public key, so the fingerprint V12 enrolled must have been computed over
//! the same wire-form bytes; a key enrolled from other bytes (V12's own test fixtures use
//! raw 32-byte values) is refused here as a malformed blob or a changed key.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};

use serde::Serialize;

use super::path::SshFilePath;
use super::wire::{
    algorithm_for_key_type, base64_decode, base64_encode, check_blob, known_hosts_key_type,
    openssh_sha256, KeyBlobProblem,
};
use crate::sandbox_contract::destinations::{Authority, DestinationHost};
use crate::sandbox_contract::remote::{
    EnrollmentGeneration, HostEnrollment, HostKey, HostKeyAlgorithm, HostKeyProblem,
    HostKeyRefusal, KnownHosts, RemoteHostId,
};

/// The longest `known_hosts` text read back.
pub const MAX_KNOWN_HOSTS_BYTES: usize = 64 * 1024;
/// The SSH port; a host on it is written without brackets or port in `known_hosts`.
pub const DEFAULT_SSH_PORT: u16 = 22;

/// Why rendered `known_hosts` text was refused: it is not what this module renders.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum KnownHostsProblem {
    Empty,
    TooLarge {
        max_bytes: u64,
    },
    NotAscii,
    CarriageReturn,
    NoFinalNewline,
    /// The file holds more than the one line for the enrolled key.
    MoreThanOneLine,
    /// A tab or another control character.
    ControlCharacter,
    CommentLine,
    /// An `@cert-authority` or `@revoked` marker.
    Marker,
    /// A hashed host name (`|1|...`).
    HashedHost,
    /// A wildcard, a negation or a list of hosts.
    HostPattern,
    /// Not exactly host, key type and key, separated by single spaces.
    FieldCount {
        fields: u64,
    },
    /// The line names another host or port than the target.
    WrongHost,
    UnsupportedKeyType,
    Base64,
    /// The text differs from the rendering of the key it holds.
    NotCanonical,
}

/// Which file step failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperation {
    Create,
    Write,
    Sync,
    Read,
}

/// Why a host key, a `known_hosts` text or file was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnownHostsRefusal {
    /// The key blob is not one public key of its algorithm.
    KeyBlob { problem: KeyBlobProblem },
    /// V12 refused the key bytes.
    HostKey { problem: HostKeyProblem },
    /// V12's `KnownHosts` refused the key: the host is not enrolled, or it is enrolled
    /// with another key (VM-W41).
    Enrollment { refusal: HostKeyRefusal },
    /// The key is still enrolled, but under a later enrollment than the one rendered.
    StaleEnrollment {
        host: RemoteHostId,
        rendered: EnrollmentGeneration,
        current: EnrollmentGeneration,
    },
    /// The text is not what this module renders.
    NotRendered { problem: KnownHostsProblem },
    /// Something exists at the path; it is never overwritten or followed.
    PathExists,
    File {
        operation: FileOperation,
        error: String,
    },
}

impl fmt::Display for KnownHostsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyBlob { problem } => write!(f, "{problem}"),
            Self::HostKey { problem } => write!(f, "{problem}"),
            Self::Enrollment { refusal } => write!(f, "{refusal}"),
            Self::StaleEnrollment { host, .. } => write!(
                f,
                "the known_hosts file was rendered for an earlier enrollment of host {host}"
            ),
            Self::NotRendered { problem } => write!(
                f,
                "the known_hosts text is not the single line rendered for the enrolled key \
                 ({problem:?})"
            ),
            Self::PathExists => f.write_str(
                "something already exists at the known_hosts path; it is not overwritten",
            ),
            Self::File { operation, error } => {
                write!(f, "known_hosts file {operation:?} failed: {error}")
            }
        }
    }
}

impl std::error::Error for KnownHostsRefusal {}

fn not_rendered(problem: KnownHostsProblem) -> KnownHostsRefusal {
    KnownHostsRefusal::NotRendered { problem }
}

fn file_failed(operation: FileOperation, error: &io::Error) -> KnownHostsRefusal {
    KnownHostsRefusal::File {
        operation,
        error: error.to_string(),
    }
}

/// Where the management client connects: the enrolled host and the network authority
/// (V02's canonical host and port, port 0 refused) it is reached at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshTarget {
    host: RemoteHostId,
    authority: Authority,
}

impl SshTarget {
    /// The enrolled `host`, reached at `authority`. V02's parser has already refused
    /// whitespace, `@`, `%`, leading `-`, single labels, non-canonical IP literals and
    /// port 0, so the host is one word OpenSSH reads literally.
    pub fn new(host: RemoteHostId, authority: Authority) -> Self {
        Self { host, authority }
    }

    pub fn host(&self) -> RemoteHostId {
        self.host
    }

    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    pub fn port(&self) -> u16 {
        self.authority.port.get()
    }

    /// The host word of the `ssh` command line: the name or address, an IPv6 address
    /// without brackets.
    pub fn command_host(&self) -> String {
        match &self.authority.host {
            DestinationHost::Name(name) => name.as_str().to_owned(),
            DestinationHost::Address(address) => address.to_string(),
        }
    }

    /// The host as OpenSSH writes and looks it up in `known_hosts`.
    pub fn known_hosts_pattern(&self) -> String {
        let host = self.command_host();
        if self.port() == DEFAULT_SSH_PORT {
            host
        } else {
            format!("[{host}]:{}", self.port())
        }
    }
}

/// An enrolled host key in SSH wire form, accepted only while V12's [`KnownHosts`]
/// accepts it for the target's host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolledHostKey {
    target: SshTarget,
    algorithm: HostKeyAlgorithm,
    blob: Vec<u8>,
    key: HostKey,
    enrollment: HostEnrollment,
}

impl EnrolledHostKey {
    /// The key `blob` of `algorithm` for `target`. The blob must be one wire-form public
    /// key of the algorithm, and [`KnownHosts::verify`] must accept it for the target's
    /// host; its refusal is returned unchanged.
    pub fn new(
        known: &KnownHosts,
        target: SshTarget,
        algorithm: HostKeyAlgorithm,
        blob: Vec<u8>,
    ) -> Result<Self, KnownHostsRefusal> {
        let key = HostKey::new(algorithm, blob.clone())
            .map_err(|problem| KnownHostsRefusal::HostKey { problem })?;
        check_blob(algorithm, &blob).map_err(|problem| KnownHostsRefusal::KeyBlob { problem })?;
        let enrollment = known
            .verify(&target.host, &key)
            .map_err(|refusal| KnownHostsRefusal::Enrollment { refusal })?
            .clone();
        Ok(Self {
            target,
            algorithm,
            blob,
            key,
            enrollment,
        })
    }

    pub fn target(&self) -> &SshTarget {
        &self.target
    }

    pub fn algorithm(&self) -> HostKeyAlgorithm {
        self.algorithm
    }

    /// The key as V12 knows it.
    pub fn host_key(&self) -> &HostKey {
        &self.key
    }

    /// The enrollment the key was accepted under.
    pub fn enrollment(&self) -> &HostEnrollment {
        &self.enrollment
    }

    /// OpenSSH's `SHA256:` fingerprint of the key, as its warnings and `ssh-keygen -l`
    /// print it.
    pub fn openssh_fingerprint(&self) -> String {
        openssh_sha256(&self.blob)
    }

    /// The one `known_hosts` line for the key, LF-terminated.
    pub fn known_hosts_line(&self) -> String {
        format!(
            "{} {} {}\n",
            self.target.known_hosts_pattern(),
            known_hosts_key_type(self.algorithm),
            base64_encode(&self.blob)
        )
    }

    /// Refuses the key once it is no longer the host's current enrollment: V12's
    /// refusal when the host was retired or enrolled with another key, a stale
    /// generation when it was re-enrolled with this one.
    pub fn check_current(&self, known: &KnownHosts) -> Result<(), KnownHostsRefusal> {
        let current = known
            .verify(&self.target.host, &self.key)
            .map_err(|refusal| KnownHostsRefusal::Enrollment { refusal })?;
        if current.generation != self.enrollment.generation {
            return Err(KnownHostsRefusal::StaleEnrollment {
                host: self.target.host,
                rendered: self.enrollment.generation,
                current: current.generation,
            });
        }
        Ok(())
    }
}

/// A `known_hosts` file this module wrote for one enrolled key. It is the only way to
/// name a host-key file in an invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownHostsFile {
    path: SshFilePath,
    key: EnrolledHostKey,
}

impl KnownHostsFile {
    /// Writes the key's one line to a new file at `path` and syncs it. Anything already
    /// at `path`, a link included, is refused and left alone, so the caller should pick
    /// a fresh path in a directory only it can write. The file holds public data and gets
    /// the platform's default permissions.
    pub fn write(key: EnrolledHostKey, path: SshFilePath) -> Result<Self, KnownHostsRefusal> {
        let line = key.known_hosts_line();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.as_path())
            .map_err(|error| {
                // Windows reports a create over a directory as access denied.
                if error.kind() == ErrorKind::AlreadyExists
                    || std::fs::symlink_metadata(path.as_path()).is_ok()
                {
                    KnownHostsRefusal::PathExists
                } else {
                    file_failed(FileOperation::Create, &error)
                }
            })?;
        file.write_all(line.as_bytes())
            .map_err(|error| file_failed(FileOperation::Write, &error))?;
        file.sync_all()
            .map_err(|error| file_failed(FileOperation::Sync, &error))?;
        Ok(Self { path, key })
    }

    pub fn path(&self) -> &SshFilePath {
        &self.path
    }

    pub fn key(&self) -> &EnrolledHostKey {
        &self.key
    }

    /// Reads the file back and parses it strictly: it must still hold exactly the line
    /// rendered for a key that is still the host's current enrollment.
    pub fn read_back(&self, known: &KnownHosts) -> Result<EnrolledHostKey, KnownHostsRefusal> {
        self.key.check_current(known)?;
        let mut text = Vec::new();
        File::open(self.path.as_path())
            .and_then(|file| {
                file.take(
                    u64::try_from(MAX_KNOWN_HOSTS_BYTES)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                )
                .read_to_end(&mut text)
            })
            .map_err(|error| file_failed(FileOperation::Read, &error))?;
        parse_known_hosts(&text, known, &self.key.target)
    }
}

/// Parses `known_hosts` text for `target` back into its enrolled key, accepting only
/// what [`EnrolledHostKey::known_hosts_line`] renders: one LF-terminated line naming the
/// target exactly, a supported key type, canonical base64 of a well-formed blob, and a key
/// V12's [`KnownHosts::verify`] accepts for the target's host.
pub fn parse_known_hosts(
    text: &[u8],
    known: &KnownHosts,
    target: &SshTarget,
) -> Result<EnrolledHostKey, KnownHostsRefusal> {
    if text.len() > MAX_KNOWN_HOSTS_BYTES {
        return Err(not_rendered(KnownHostsProblem::TooLarge {
            max_bytes: u64::try_from(MAX_KNOWN_HOSTS_BYTES).unwrap_or(u64::MAX),
        }));
    }
    let text = std::str::from_utf8(text)
        .ok()
        .filter(|text| text.is_ascii())
        .ok_or(not_rendered(KnownHostsProblem::NotAscii))?;
    if text.contains('\r') {
        return Err(not_rendered(KnownHostsProblem::CarriageReturn));
    }
    if text.is_empty() {
        return Err(not_rendered(KnownHostsProblem::Empty));
    }
    let body = text
        .strip_suffix('\n')
        .ok_or(not_rendered(KnownHostsProblem::NoFinalNewline))?;
    if body.contains('\n') {
        return Err(not_rendered(KnownHostsProblem::MoreThanOneLine));
    }
    if body.is_empty() {
        return Err(not_rendered(KnownHostsProblem::Empty));
    }
    if body.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(not_rendered(KnownHostsProblem::ControlCharacter));
    }
    if body.starts_with('#') {
        return Err(not_rendered(KnownHostsProblem::CommentLine));
    }
    if body.starts_with('@') {
        return Err(not_rendered(KnownHostsProblem::Marker));
    }
    let fields: Vec<&str> = body.split(' ').collect();
    let pattern = fields.first().copied().unwrap_or_default();
    if pattern.starts_with('|') {
        return Err(not_rendered(KnownHostsProblem::HashedHost));
    }
    if pattern.contains(['*', '?', '!', ',']) {
        return Err(not_rendered(KnownHostsProblem::HostPattern));
    }
    let [pattern, key_type, encoded] = fields.as_slice() else {
        return Err(not_rendered(KnownHostsProblem::FieldCount {
            fields: u64::try_from(fields.len()).unwrap_or(u64::MAX),
        }));
    };
    if *pattern != target.known_hosts_pattern() {
        return Err(not_rendered(KnownHostsProblem::WrongHost));
    }
    let algorithm = algorithm_for_key_type(key_type)
        .ok_or(not_rendered(KnownHostsProblem::UnsupportedKeyType))?;
    let blob = base64_decode(encoded).ok_or(not_rendered(KnownHostsProblem::Base64))?;
    let key = EnrolledHostKey::new(known, target.clone(), algorithm, blob)?;
    if key.known_hosts_line() != text {
        return Err(not_rendered(KnownHostsProblem::NotCanonical));
    }
    Ok(key)
}
