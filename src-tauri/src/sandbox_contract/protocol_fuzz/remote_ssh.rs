//! The OpenSSH adapter's readers under the fuzzer (M16A; VM-W41 "host-key changes
//! rejected", VM part §6.3 step 5, VM-CP-33, VM-P42; VM-W50): `parse_known_hosts` on
//! mutated `known_hosts` text and key blobs, and `classify` on arbitrary exit statuses,
//! output lengths and stderr.
//!
//! `known_hosts`, against four enrolled hosts of every key algorithm, on and off port 22
//! and by name, IPv4 and IPv6 address. Properties, beside no panic and the same result
//! twice: a host accepts exactly one text, the line rendered for its enrolled key, and
//! returns exactly that key; a refusal for another key is V12's `Changed` for that host
//! and its enrolled fingerprint; nothing over [`MAX_KNOWN_HOSTS_BYTES`] is read.
//!
//! `classify`, beside no panic and the same result twice: the documented order (a client
//! not started, the deadline, a port fault, a stream over its bound, no exit status,
//! then the status) gives exactly the documented outcome; 0 to 254 is the remote status
//! whatever stderr says and only 0 succeeds; any other status but 255 is uncertain; 255
//! never becomes a remote exit, a host-key mismatch carries the target's host and
//! enrolled fingerprint and ends delegation, a reported fingerprint has OpenSSH's form,
//! and outcomes before a session say the command did not run. Two metamorphic checks on
//! 255: LF and CRLF line endings classify alike, and a junk line after the last one makes
//! the result uncertain, so only a whole last line is ever recognised.

use std::collections::BTreeSet;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use super::driver::{fuzz, fuzz_with, Regression, Run, Verdict};
use super::mutate::{decimal_fields, runs, variant, Encoding, Field, Grammar};
use crate::foundation::evidence::ProviderKind;
use crate::foundation::ids::{digest, MonotonicTime};
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::destinations::{Authority, DestinationPort};
use crate::sandbox_contract::remote::{
    EnrollmentEvidence, EnrollmentPolicy, ExecutionContext, HostKey, HostKeyAlgorithm,
    HostKeyRefusal, KnownHosts, ManagementAction, ManagementIdentity, OptionTerminator,
    ProgramPath, RegionName, RemoteAccountName, RemoteCommand, RemoteHostId, RemoteInvocation,
    RemoteShellKind, UncertainCause, MAX_HOST_KEY_BYTES,
};
use crate::sandbox_contract::remote_ssh::{
    classify, parse_known_hosts, render_invocation, ConnectionFailure, EnrolledHostKey,
    HostKeyEvidence, IdentityFile, KnownHostsFile, KnownHostsProblem, KnownHostsRefusal,
    OutputStream, PortFailure, SshFilePath, SshInvocation, SshLimits, SshOutcome, SshOutput,
    SshTarget, SshTermination, TimeoutPhase, MAX_KNOWN_HOSTS_BYTES, MIN_RSA_MODULUS_BITS,
};

/// Mutated `known_hosts` texts per run, each checked against every host.
const KNOWN_HOSTS_ITERATIONS: u64 = 25_000;
/// Mutated client reports per run.
const CLASSIFY_ITERATIONS: u64 = 50_000;
/// The output bounds of the classified invocation.
const STDOUT_BOUND: u64 = 512;
const STDERR_BOUND: u64 = 1_024;

fn bytes_of(length: usize) -> u64 {
    u64::try_from(length).unwrap()
}

/// An RFC 4251 `string`: a big-endian length and the bytes.
fn ssh_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

/// A wire-form public key of `algorithm` filled from `seed`: 32 bytes for Ed25519, an
/// uncompressed point for ECDSA, exponent 65537 and a 2048-bit modulus for RSA.
fn blob(algorithm: HostKeyAlgorithm, seed: u8) -> Vec<u8> {
    match algorithm {
        HostKeyAlgorithm::Ed25519 => [ssh_string(b"ssh-ed25519"), ssh_string(&[seed; 32])].concat(),
        HostKeyAlgorithm::EcdsaNistp256 | HostKeyAlgorithm::EcdsaNistp384 => {
            let (name, curve, coordinate) = if algorithm == HostKeyAlgorithm::EcdsaNistp256 {
                ("ecdsa-sha2-nistp256", "nistp256", 32)
            } else {
                ("ecdsa-sha2-nistp384", "nistp384", 48)
            };
            let mut point = vec![0x04];
            point.extend(std::iter::repeat_n(seed, 2 * coordinate));
            [
                ssh_string(name.as_bytes()),
                ssh_string(curve.as_bytes()),
                ssh_string(&point),
            ]
            .concat()
        }
        HostKeyAlgorithm::RsaSha2_512 => {
            let mut modulus = vec![0x00, 0x80 | seed];
            modulus.extend(std::iter::repeat_n(seed | 1, 255));
            [
                ssh_string(b"ssh-rsa"),
                ssh_string(&[0x01, 0x00, 0x01]),
                ssh_string(&modulus),
            ]
            .concat()
        }
    }
}

fn host_id(number: u8) -> RemoteHostId {
    RemoteHostId::of(
        ProviderKind::Crusoe,
        &RegionName::new("us-east-1").unwrap(),
        &digest("yougori/test/protocol-fuzz/instance/v1", &[&[number]]),
    )
}

fn client_key() -> CredentialRef {
    CredentialRef::from_digest(digest(
        "yougori/test/protocol-fuzz/ssh-client-key/v1",
        &[b"mgmt"],
    ))
}

/// One enrolled host: its `known_hosts`, target, key, rendered line and a management
/// identity.
struct World {
    host: RemoteHostId,
    known: KnownHosts,
    target: SshTarget,
    key: EnrolledHostKey,
    line: Vec<u8>,
    identity: ManagementIdentity,
}

/// Host `number` at `authority` (port 22 when none is written), enrolled through the
/// provider API with a key of `algorithm`.
fn world(number: u8, authority: &str, algorithm: HostKeyAlgorithm) -> World {
    let mut known = KnownHosts::new();
    let host = host_id(number);
    let blob = blob(algorithm, number);
    let host_key = HostKey::new(algorithm, blob.clone()).unwrap();
    let enrollment = known
        .enroll(
            host,
            &host_key,
            EnrollmentEvidence::ProviderApi {
                reported: host_key.fingerprint(),
            },
            EnrollmentPolicy::default(),
            MonotonicTime::ZERO,
        )
        .unwrap();
    let identity = ManagementIdentity::new(
        &enrollment,
        RemoteAccountName::new("yougori").unwrap(),
        client_key(),
        RemoteShellKind::Posix,
        ManagementAction::ALL
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
    )
    .unwrap();
    let authority = Authority::parse(authority, DestinationPort::new(22).unwrap()).unwrap();
    let target = SshTarget::new(host, authority);
    let key = EnrolledHostKey::new(&known, target.clone(), algorithm, blob).unwrap();
    let line = key.known_hosts_line().into_bytes();
    World {
        host,
        known,
        target,
        key,
        line,
        identity,
    }
}

fn worlds() -> Vec<World> {
    vec![
        world(1, "203.0.113.7:2222", HostKeyAlgorithm::Ed25519),
        world(2, "mgmt.example.com", HostKeyAlgorithm::EcdsaNistp256),
        world(3, "[2001:db8::7]", HostKeyAlgorithm::RsaSha2_512),
        world(4, "[2001:db8::8]:2200", HostKeyAlgorithm::EcdsaNistp384),
    ]
}

/// A `known_hosts` line for `world`'s target holding another blob.
fn line_with(world: &World, key_type: &str, blob: &[u8]) -> Vec<u8> {
    format!(
        "{} {key_type} {}\n",
        world.target.known_hosts_pattern(),
        STANDARD.encode(blob)
    )
    .into_bytes()
}

fn known_hosts_seeds(worlds: &[World]) -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = worlds.iter().map(|world| world.line.clone()).collect();
    seeds.push(line_with(
        &worlds[0],
        "ssh-ed25519",
        &blob(HostKeyAlgorithm::Ed25519, 99),
    ));
    seeds.push(line_with(
        &worlds[1],
        "ssh-ed25519",
        &blob(HostKeyAlgorithm::Ed25519, 2),
    ));
    seeds.push(line_with(
        &worlds[2],
        "ssh-rsa",
        &blob(HostKeyAlgorithm::RsaSha2_512, 9),
    ));
    seeds
}

/// The length fields of the RFC 4251 strings in a key blob.
fn blob_fields(blob: &[u8]) -> Vec<Field> {
    let mut fields = Vec::new();
    let mut offset = 0;
    while offset + 4 <= blob.len() {
        fields.push(Field::binary(offset, 4));
        let length = u32::from_be_bytes([
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ]);
        offset = offset
            .saturating_add(4)
            .saturating_add(usize::try_from(length).unwrap());
    }
    fields
}

fn label_known_hosts(result: &Result<EnrolledHostKey, KnownHostsRefusal>) -> String {
    match result {
        Ok(_) => "accepted".to_owned(),
        Err(KnownHostsRefusal::NotRendered { problem }) => {
            format!("refused:{}", variant(&format!("{problem:?}")))
        }
        Err(KnownHostsRefusal::KeyBlob { problem }) => {
            format!("refused:KeyBlob:{}", variant(&format!("{problem:?}")))
        }
        Err(KnownHostsRefusal::Enrollment { refusal }) => {
            format!("refused:{}", variant(&format!("{refusal:?}")))
        }
        Err(other) => format!("refused:{}", variant(&format!("{other:?}"))),
    }
}

fn check_known_hosts(worlds: &[World], input: &[u8]) -> Verdict {
    let mut labels = Vec::with_capacity(worlds.len());
    for world in worlds {
        let first = parse_known_hosts(input, &world.known, &world.target);
        ensure!(
            first == parse_known_hosts(input, &world.known, &world.target),
            "two parses of one text differ"
        );
        match &first {
            Ok(key) => {
                ensure!(
                    input == world.line.as_slice(),
                    "{} accepted a text other than its rendered line",
                    world.target.known_hosts_pattern()
                );
                ensure!(
                    *key == world.key,
                    "the accepted key is not the enrolled one"
                );
            }
            Err(refusal) => {
                ensure!(
                    input != world.line.as_slice(),
                    "the rendered line was refused: {refusal}"
                );
                if input.len() > MAX_KNOWN_HOSTS_BYTES {
                    ensure!(
                        matches!(
                            refusal,
                            KnownHostsRefusal::NotRendered {
                                problem: KnownHostsProblem::TooLarge { .. }
                            }
                        ),
                        "a {}-byte text refused with {refusal:?}",
                        input.len()
                    );
                }
                match refusal {
                    KnownHostsRefusal::Enrollment {
                        refusal: HostKeyRefusal::Changed { host, enrolled, .. },
                    } => ensure!(
                        *host == world.host && *enrolled == world.key.enrollment().fingerprint,
                        "a changed key refused for another host or enrollment"
                    ),
                    KnownHostsRefusal::Enrollment { .. }
                    | KnownHostsRefusal::StaleEnrollment { .. }
                    | KnownHostsRefusal::PathExists
                    | KnownHostsRefusal::File { .. } => {
                        return Err(format!("a refusal parsing cannot give: {refusal:?}"))
                    }
                    _ => {}
                }
            }
        }
        labels.push(label_known_hosts(&first));
    }
    let chosen = worlds
        .iter()
        .position(|world| {
            input.starts_with(format!("{} ", world.target.known_hosts_pattern()).as_bytes())
        })
        .unwrap_or(0);
    Ok(labels.swap_remove(chosen))
}

/// Texts that reach each refusal, for the first host (Ed25519 at `[203.0.113.7]:2222`).
const KNOWN_HOSTS_REGRESSIONS: &[Regression] = &[
    Regression {
        expect: "accepted",
        input: b"[203.0.113.7]:2222 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n",
    },
    Regression {
        expect: "refused:CarriageReturn",
        input: b"[203.0.113.7]:2222 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\r\n",
    },
    Regression {
        expect: "refused:NoFinalNewline",
        input: b"[203.0.113.7]:2222 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
    },
    Regression {
        expect: "refused:MoreThanOneLine",
        input: b"[203.0.113.7]:2222 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n\
                 [203.0.113.7]:2222 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC\n",
    },
    Regression {
        expect: "refused:Changed",
        input: b"[203.0.113.7]:2222 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC\n",
    },
    Regression {
        expect: "refused:KeyBlob:Truncated",
        input: b"[203.0.113.7]:2222 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n",
    },
    Regression {
        expect: "refused:KeyBlob:TrailingBytes",
        input: b"[203.0.113.7]:2222 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAA==\n",
    },
    Regression {
        expect: "refused:Base64",
        input: b"[203.0.113.7]:2222 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF=\n",
    },
    Regression {
        expect: "refused:Base64",
        input: b"[203.0.113.7]:2222 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB=\n",
    },
    Regression {
        expect: "refused:UnsupportedKeyType",
        input: b"[203.0.113.7]:2222 ssh-dss \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n",
    },
    Regression {
        expect: "refused:WrongHost",
        input: b"203.0.113.7 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n",
    },
    Regression {
        expect: "refused:HostPattern",
        input: b"[203.0.113.7]:2222,[203.0.113.8]:2222 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n",
    },
    Regression {
        expect: "refused:FieldCount",
        input: b"[203.0.113.7]:2222  ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n",
    },
    Regression {
        expect: "refused:ControlCharacter",
        input: b"[203.0.113.7]:2222\tssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n",
    },
    Regression {
        expect: "refused:HashedHost",
        input: b"|1|c2FsdA==|aGFzaA== ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n",
    },
    Regression {
        expect: "refused:Marker",
        input: b"@cert-authority [203.0.113.7]:2222 ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n",
    },
    Regression {
        expect: "refused:CommentLine",
        input: b"# [203.0.113.7]:2222\n",
    },
    Regression {
        expect: "refused:NotAscii",
        input: b"[203.0.113.7]:2222 ssh-ed25519 \xff\n",
    },
    Regression {
        expect: "refused:Empty",
        input: b"\n",
    },
    Regression {
        expect: "refused:Empty",
        input: b"",
    },
];

#[test]
fn mutated_known_hosts_texts_accept_only_the_rendered_line() {
    let worlds = worlds();
    let seeds = known_hosts_seeds(&worlds);
    let tokens: [&[u8]; 20] = [
        b" ",
        b"\n",
        b"\r\n",
        b"\t",
        b"#",
        b"@cert-authority ",
        b"|1|",
        b"*",
        b"?",
        b"!",
        b",",
        b"=",
        b"[",
        b"]",
        b":22",
        b"ssh-ed25519",
        b"ssh-rsa",
        b"ecdsa-sha2-nistp256",
        b"ecdsa-sha2-nistp384",
        b"rsa-sha2-512",
    ];
    let text = Grammar {
        seeds: seeds.clone(),
        dictionary: tokens.iter().map(|token| token.to_vec()).collect(),
        limits: vec![0, 22, 2200, 2222, 65_535],
        fields: decimal_fields,
        max_len: 3_000,
    };
    let blobs = Grammar {
        seeds: [
            HostKeyAlgorithm::Ed25519,
            HostKeyAlgorithm::EcdsaNistp256,
            HostKeyAlgorithm::EcdsaNistp384,
            HostKeyAlgorithm::RsaSha2_512,
        ]
        .into_iter()
        .map(|algorithm| blob(algorithm, 1))
        .collect(),
        dictionary: vec![
            ssh_string(b"ssh-ed25519"),
            ssh_string(b"nistp256"),
            ssh_string(b"nistp384"),
            vec![0x04],
            vec![0x00],
            vec![0x80],
        ],
        limits: vec![
            32,
            65,
            97,
            MIN_RSA_MODULUS_BITS / 8,
            bytes_of(MAX_HOST_KEY_BYTES),
        ],
        fields: blob_fields,
        max_len: 2_048,
    };
    let run = Run {
        target: "remote_ssh::parse_known_hosts",
        seed: 0x00E0_155A_0000_0001,
        iterations: KNOWN_HOSTS_ITERATIONS,
        regressions: KNOWN_HOSTS_REGRESSIONS,
    };
    let report = fuzz_with(
        run,
        &seeds,
        |rng, used| {
            if !rng.one_in(3) {
                return text.generate(rng, used);
            }
            // A seed line whose key blob is mutated and then written as canonical base64,
            // so the blob checks behind the base64 are reached.
            let line = String::from_utf8(rng.pick(&seeds).clone()).unwrap();
            let (head, encoded) = line.trim_end_matches('\n').rsplit_once(' ').unwrap();
            let mut blob = STANDARD.decode(encoded).unwrap();
            for _ in 0..rng.between(1, 3) {
                blobs.mutate(rng, &mut blob);
            }
            blob.truncate(blobs.max_len);
            format!("{head} {}\n", STANDARD.encode(&blob)).into_bytes()
        },
        |input| check_known_hosts(&worlds, input),
    );
    assert_eq!(report.iterations, KNOWN_HOSTS_ITERATIONS);
    // `NotCanonical` is not listed: once the host, the key type and canonical base64 are
    // checked exactly, the re-rendered line cannot differ, so that refusal is a second
    // guard no text reaches.
    report.assert_reached(
        "remote_ssh::parse_known_hosts",
        &[
            "accepted",
            "refused:Changed",
            "refused:KeyBlob",
            "refused:Base64",
            "refused:WrongHost",
            "refused:FieldCount",
            "refused:NoFinalNewline",
            "refused:UnsupportedKeyType",
            "refused:HostPattern",
            "refused:ControlCharacter",
        ],
    );
}

#[test]
fn known_hosts_size_limit_holds_at_its_boundary() {
    let worlds = worlds();
    let first = &worlds[0];
    // The rendered line padded to the limit is refused as not rendered; one byte more is
    // refused as too large before it is read.
    let mut text = first.line.clone();
    text.resize(MAX_KNOWN_HOSTS_BYTES, b'\n');
    assert_eq!(
        check_known_hosts(&worlds, &text).unwrap(),
        "refused:MoreThanOneLine"
    );
    text.push(b'\n');
    assert_eq!(
        check_known_hosts(&worlds, &text).unwrap(),
        "refused:TooLarge"
    );
    // Every host accepts its own line and refuses every other host's.
    for world in &worlds {
        let label = check_known_hosts(&worlds, &world.line).unwrap();
        assert_eq!(label, "accepted");
        for other in &worlds {
            let accepted = parse_known_hosts(&other.line, &world.known, &world.target).is_ok();
            assert_eq!(accepted, std::ptr::eq(world, other));
        }
    }
}

/// The classified invocation's fixture: an enrolled host, its written `known_hosts` file,
/// an identity file path and a management invocation, in a scratch directory.
struct Fixture {
    world: World,
    _scratch: tempfile::TempDir,
    known_hosts: KnownHostsFile,
    identity_file: IdentityFile,
    invocation: RemoteInvocation,
}

impl Fixture {
    fn new() -> Self {
        let world = world(1, "203.0.113.7:2222", HostKeyAlgorithm::Ed25519);
        let scratch = tempfile::Builder::new()
            .prefix("protocol-fuzz-ssh-")
            .tempdir()
            .unwrap();
        let base = scratch.path().to_str().unwrap().replace('\\', "/");
        let path = |name: &str| SshFilePath::new(format!("{base}/{name}")).unwrap();
        let known_hosts = KnownHostsFile::write(world.key.clone(), path("known_hosts")).unwrap();
        // Rendering never opens the identity file, so a fixed path keeps the seeds that
        // quote it (and so every mutated input) the same from run to run.
        let identity = if cfg!(windows) {
            "C:/protocol-fuzz/id_ed25519"
        } else {
            "/protocol-fuzz/id_ed25519"
        };
        let identity_file = IdentityFile::new(client_key(), SshFilePath::new(identity).unwrap());
        let command = RemoteCommand::new(
            ProgramPath::new("/opt/yougori/bin/yougori-remote").unwrap(),
            OptionTerminator::DoubleDash,
        )
        .flag("--launch-vm")
        .unwrap()
        .operand("vm-one")
        .unwrap();
        let invocation = RemoteInvocation::new(
            &world.identity,
            &world.known,
            ManagementAction::LaunchVm,
            ExecutionContext::RemoteHostShell { host: world.host },
            &command,
        )
        .unwrap();
        Self {
            world,
            _scratch: scratch,
            known_hosts,
            identity_file,
            invocation,
        }
    }

    fn rendered(&self) -> SshInvocation<'_> {
        let limits = SshLimits::new(
            10,
            10,
            2,
            Duration::from_secs(120),
            STDOUT_BOUND,
            STDERR_BOUND,
        )
        .unwrap();
        render_invocation(
            &self.world.identity,
            &self.world.known,
            &self.known_hosts,
            &self.identity_file,
            limits,
            &self.invocation,
        )
        .unwrap()
    }
}

const PORT_FAILURES: [PortFailure; 4] = [
    PortFailure::PipeMissing,
    PortFailure::ThreadNotStarted,
    PortFailure::ReadFailed,
    PortFailure::WaitFailed,
];

/// A client report from bytes: the first selects how the client ended, the next four are
/// a big-endian exit status, the next two the stdout length and the rest is stderr.
fn output_of(input: &[u8]) -> SshOutput {
    let kind = input.first().copied().unwrap_or(0);
    let code = input
        .get(1..5)
        .map_or(0, |bytes| i32::from_be_bytes(bytes.try_into().unwrap()));
    let stdout = input
        .get(5..7)
        .map_or(0, |bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
    let termination = match kind % 8 {
        0..=3 => SshTermination::Exited { code },
        4 => SshTermination::NoExitStatus,
        5 => SshTermination::DeadlineReached,
        6 => SshTermination::NotStarted,
        _ => SshTermination::PortFailed {
            failure: PORT_FAILURES[usize::from(kind / 8) % 4],
        },
    };
    // The port reads at most one byte over each bound.
    let stdout = usize::from(stdout).min(usize::try_from(STDOUT_BOUND).unwrap() + 1);
    SshOutput {
        termination,
        stdout: vec![b'o'; stdout],
        stderr: input.get(7..).unwrap_or_default().to_vec(),
    }
}

/// The bytes [`output_of`] reads as `kind`, `code`, `stdout` bytes and `stderr`.
fn output_bytes(kind: u8, code: i32, stdout: u16, stderr: &str) -> Vec<u8> {
    let mut bytes = vec![kind];
    bytes.extend_from_slice(&code.to_be_bytes());
    bytes.extend_from_slice(&stdout.to_be_bytes());
    bytes.extend_from_slice(stderr.as_bytes());
    bytes
}

/// The exit status, the stdout length and the decimal numbers of stderr.
fn classify_fields(input: &[u8]) -> Vec<Field> {
    let mut fields = Vec::new();
    if input.len() >= 5 {
        fields.push(Field::binary(1, 4));
    }
    if input.len() >= 7 {
        fields.push(Field::binary(5, 2));
    }
    fields.extend(runs(
        input,
        7,
        input.len(),
        u8::is_ascii_digit,
        Encoding::Decimal,
    ));
    fields
}

const CHANGED: &str = "\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n\
The fingerprint for the ED25519 key sent by the remote host is\r\n\
SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.\r\n\
Offending ED25519 key in /run/kh:1\r\n\
ED25519 host key for [203.0.113.7]:2222 has changed and you have requested strict \
checking.\r\n\
Host key verification failed.\r\n";

fn classify_seeds(identity_file: &str) -> Vec<Vec<u8>> {
    let refused = format!(
        "Load key \"{identity_file}\": invalid format\r\nyougori@203.0.113.7: Permission \
         denied (publickey,password).\r\n"
    );
    let stderrs = [
        CHANGED,
        "Host key verification failed.\r\n",
        "Unable to negotiate with 203.0.113.7 port 2222: no matching host key type found. \
         Their offer: ssh-rsa\r\n",
        "Unable to negotiate with 203.0.113.7 port 2222: no matching cipher found. Their \
         offer: aes128-cbc\r\n",
        "yougori@203.0.113.7: Permission denied (publickey).\r\n",
        refused.as_str(),
        "ssh: connect to host 203.0.113.7 port 2222: Connection refused\r\n",
        "ssh: connect to host 203.0.113.7 port 2222: No route to host\r\n",
        "ssh: connect to host 203.0.113.7 port 2222: Connection timed out\r\n",
        "ssh: connect to host 203.0.113.7 port 2222: Invalid argument\r\n",
        "ssh: Could not resolve hostname 203.0.113.7: Name or service not known\r\n",
        "Connection timed out during banner exchange\r\nConnection to 203.0.113.7 port 2222 \
         timed out\r\n",
        "kex_exchange_identification: read: Connection reset by peer\r\nConnection reset by \
         203.0.113.7 port 2222\r\n",
        "Timeout, server 203.0.113.7 not responding.\r\n",
        "Connection to 203.0.113.7 closed by remote host.\r\n",
        "",
    ];
    let mut seeds: Vec<Vec<u8>> = stderrs
        .iter()
        .map(|stderr| output_bytes(0, 255, 0, stderr))
        .collect();
    seeds.push(output_bytes(0, 0, 12, ""));
    seeds.push(output_bytes(1, 1, 0, "Host key verification failed.\r\n"));
    seeds.push(output_bytes(
        4,
        0,
        0,
        "Connection to 203.0.113.7 closed by remote host.\n",
    ));
    seeds.push(output_bytes(5, 0, 0, ""));
    seeds.push(output_bytes(6, 0, 0, ""));
    seeds.push(output_bytes(7, 0, 0, ""));
    seeds.push(output_bytes(0, -1, 513, ""));
    seeds
}

/// `stderr` with every bare line feed written as CRLF.
fn crlf(stderr: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(stderr.len() * 2);
    for (index, byte) in stderr.iter().enumerate() {
        if *byte == b'\n' && (index == 0 || stderr[index - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(*byte);
    }
    out
}

fn label_outcome(outcome: &SshOutcome) -> String {
    match outcome {
        SshOutcome::HostKeyMismatch { evidence, .. } => {
            format!("HostKeyMismatch:{}", variant(&format!("{evidence:?}")))
        }
        SshOutcome::ConnectionFailed { failure } => format!("ConnectionFailed:{failure:?}"),
        SshOutcome::TimedOut { phase } => format!("TimedOut:{phase:?}"),
        SshOutcome::Uncertain { cause } => {
            format!("Uncertain:{}", variant(&format!("{cause:?}")))
        }
        SshOutcome::OutputOverBound { stream, .. } => format!("OutputOverBound:{stream:?}"),
        other => variant(&format!("{other:?}")),
    }
}

/// The properties of an exit status of 255 within the bounds: the client's own error.
fn check_client_error(
    invocation: &SshInvocation<'_>,
    output: &SshOutput,
    outcome: &SshOutcome,
) -> Result<(), String> {
    let before_session = !outcome.command_may_have_run();
    match outcome {
        SshOutcome::RemoteExit { .. } | SshOutcome::OutputOverBound { .. } => {
            return Err(format!("status 255 classified as {outcome:?}"))
        }
        SshOutcome::HostKeyMismatch {
            host,
            enrolled,
            evidence,
        } => {
            ensure!(
                *host == invocation.target().host() && *enrolled == invocation.enrolled(),
                "a mismatch for another host or key"
            );
            ensure!(
                outcome.ends_delegation() && before_session,
                "a mismatch that keeps delegation or may have run"
            );
            if let HostKeyEvidence::Changed {
                reported: Some(fingerprint),
            } = evidence
            {
                ensure!(
                    fingerprint.starts_with("SHA256:") && fingerprint.len() == 50,
                    "reported fingerprint {fingerprint:?}"
                );
            }
        }
        SshOutcome::AuthenticationRefused { methods, .. } => ensure!(
            !methods.is_empty()
                && methods.len() <= 256
                && methods.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b',' | b'@' | b'.'))
                && before_session,
            "authentication refused with methods {methods:?}"
        ),
        SshOutcome::ConnectionFailed { failure } => ensure!(
            *failure != ConnectionFailure::ClientNotStarted && before_session,
            "status 255 read as {failure:?}"
        ),
        SshOutcome::TimedOut { phase } => ensure!(
            matches!(
                phase,
                TimeoutPhase::Connect | TimeoutPhase::ServerUnresponsive
            ),
            "status 255 timed out in {phase:?}"
        ),
        SshOutcome::Uncertain { cause } => ensure!(
            matches!(
                cause,
                UncertainCause::AmbiguousResponse | UncertainCause::ConnectionLost
            ),
            "status 255 uncertain for {cause:?}"
        ),
    }
    let both = crlf(&output.stderr);
    if bytes_of(both.len()) <= STDERR_BOUND {
        let other = classify(
            invocation,
            &SshOutput {
                stderr: both,
                ..output.clone()
            },
        );
        ensure!(
            other == *outcome,
            "with CRLF endings: {other:?}; with LF: {outcome:?}"
        );
    }
    let ambiguous = SshOutcome::Uncertain {
        cause: UncertainCause::AmbiguousResponse,
    };
    let mut junk = output.stderr.clone();
    junk.extend_from_slice(b"\nx\n");
    if *outcome != ambiguous && bytes_of(junk.len()) <= STDERR_BOUND {
        let other = classify(
            invocation,
            &SshOutput {
                stderr: junk,
                ..output.clone()
            },
        );
        ensure!(
            other == ambiguous,
            "a junk line after the last one still gives {other:?}"
        );
    }
    Ok(())
}

fn check_classify(invocation: &SshInvocation<'_>, input: &[u8]) -> Verdict {
    let output = output_of(input);
    let outcome = classify(invocation, &output);
    ensure!(
        outcome == classify(invocation, &output),
        "two classifications of one report differ"
    );
    let over_stdout = bytes_of(output.stdout.len()) > STDOUT_BOUND;
    let over_stderr = bytes_of(output.stderr.len()) > STDERR_BOUND;
    let expected = match output.termination {
        SshTermination::NotStarted => Some(SshOutcome::ConnectionFailed {
            failure: ConnectionFailure::ClientNotStarted,
        }),
        SshTermination::DeadlineReached => Some(SshOutcome::TimedOut {
            phase: TimeoutPhase::Deadline,
        }),
        SshTermination::PortFailed { .. } => Some(SshOutcome::Uncertain {
            cause: UncertainCause::AmbiguousResponse,
        }),
        _ if over_stdout => Some(SshOutcome::OutputOverBound {
            stream: OutputStream::Stdout,
            max_bytes: STDOUT_BOUND,
        }),
        _ if over_stderr => Some(SshOutcome::OutputOverBound {
            stream: OutputStream::Stderr,
            max_bytes: STDERR_BOUND,
        }),
        SshTermination::NoExitStatus => Some(SshOutcome::Uncertain {
            cause: UncertainCause::ConnectionLost,
        }),
        SshTermination::Exited { code: 255 } => None,
        SshTermination::Exited { code } => Some(match u8::try_from(code) {
            Ok(code) => SshOutcome::RemoteExit { code },
            Err(_) => SshOutcome::Uncertain {
                cause: UncertainCause::AmbiguousResponse,
            },
        }),
    };
    match expected {
        Some(expected) => ensure!(
            outcome == expected,
            "{:?} classified as {outcome:?}, documented {expected:?}",
            output.termination
        ),
        None => check_client_error(invocation, &output, &outcome)?,
    }
    let success =
        output.termination == SshTermination::Exited { code: 0 } && !over_stdout && !over_stderr;
    ensure!(
        outcome.succeeded() == success,
        "{outcome:?} succeeded: {}",
        outcome.succeeded()
    );
    Ok(label_outcome(&outcome))
}

/// Reports that reach each outcome, as `output_of` reads them.
const CLASSIFY_REGRESSIONS: &[Regression] = &[
    Regression {
        expect: "RemoteExit",
        input: b"",
    },
    Regression {
        expect: "HostKeyMismatch:Unverified",
        input: b"\x00\x00\x00\x00\xff\x00\x00Host key verification failed.\r\n",
    },
    Regression {
        expect: "Uncertain:AmbiguousResponse",
        input: b"\x00\x00\x00\x00\xff\x00\x00Host key verification failed.\r\nx\r\n",
    },
    Regression {
        expect: "Uncertain:AmbiguousResponse",
        input: b"\x00\x00\x00\x00\xff\x00\x00 Host key verification failed.\n",
    },
    Regression {
        expect: "RemoteExit",
        input: b"\x00\x00\x00\x00\x00\x00\x00Host key verification failed.\r\n",
    },
    Regression {
        expect: "Uncertain:AmbiguousResponse",
        input: b"\x00\xff\xff\xff\xff\x00\x00",
    },
    Regression {
        expect: "Uncertain:AmbiguousResponse",
        input: b"\x00\x00\x00\x01\x00\x00\x00",
    },
    Regression {
        expect: "ConnectionFailed:Refused",
        input: b"\x00\x00\x00\x00\xff\x00\x00ssh: connect to host 203.0.113.7 port 2222: \
                 Connection refused\n",
    },
    Regression {
        expect: "Uncertain:AmbiguousResponse",
        input: b"\x00\x00\x00\x00\xff\x00\x00ssh: connect to host 203.0.113.7 port 22: \
                 Connection refused\n",
    },
    Regression {
        expect: "AuthenticationRefused",
        input: b"\x00\x00\x00\x00\xff\x00\x00yougori@203.0.113.7: Permission denied \
                 (publickey).\n",
    },
    Regression {
        expect: "Uncertain:AmbiguousResponse",
        input: b"\x00\x00\x00\x00\xff\x00\x00yougori@203.0.113.7: Permission denied \
                 (PublicKey).\n",
    },
    Regression {
        expect: "HostKeyMismatch:AlgorithmNotOffered",
        input: b"\x00\x00\x00\x00\xff\x00\x00Unable to negotiate with 203.0.113.7 port 2222: \
                 no matching host key type found. Their offer: ssh-rsa\n",
    },
    Regression {
        expect: "OutputOverBound:Stdout",
        input: b"\x00\x00\x00\x00\xff\x02\x01Host key verification failed.\n",
    },
    Regression {
        expect: "Uncertain:ConnectionLost",
        input: b"\x04",
    },
    Regression {
        expect: "TimedOut:Deadline",
        input: b"\x05",
    },
    Regression {
        expect: "ConnectionFailed:ClientNotStarted",
        input: b"\x06",
    },
    Regression {
        expect: "Uncertain:AmbiguousResponse",
        input: b"\x07",
    },
];

#[test]
fn arbitrary_client_reports_classify_as_documented() {
    let fixture = Fixture::new();
    let invocation = fixture.rendered();
    let identity_file = invocation.identity_file().as_str().to_owned();
    let grammar = Grammar {
        seeds: classify_seeds(&identity_file),
        dictionary: [
            "\r\n",
            "\n",
            " ",
            "\u{fffd}",
            "Host key verification failed.",
            "Permission denied (publickey).",
            "yougori@203.0.113.7: ",
            "ssh: connect to host 203.0.113.7 port 2222: ",
            "Connection refused",
            "Connection timed out",
            "Unable to negotiate with 203.0.113.7 port 2222: no matching ",
            "host key type found.",
            "cipher found.",
            "kex_exchange_identification: ",
            "Connection timed out during banner exchange",
            "Timeout, server 203.0.113.7 not responding.",
            "Connection to 203.0.113.7 closed by remote host.",
            "SHA256:",
        ]
        .iter()
        .map(|token| token.as_bytes().to_vec())
        .collect(),
        limits: vec![
            0,
            1,
            254,
            255,
            256,
            0x7FFF_FFFF,
            0x8000_0000,
            0xFFFF_FFFF,
            STDOUT_BOUND,
            STDERR_BOUND,
            2_222,
            22,
        ],
        fields: classify_fields,
        max_len: 1_500,
    };
    let run = Run {
        target: "remote_ssh::classify",
        seed: 0x00E0_1C1A_0000_0001,
        iterations: CLASSIFY_ITERATIONS,
        regressions: CLASSIFY_REGRESSIONS,
    };
    let report = fuzz(run, &grammar, |input| check_classify(&invocation, input));
    assert_eq!(report.iterations, CLASSIFY_ITERATIONS);
    report.assert_reached(
        "remote_ssh::classify",
        &[
            "RemoteExit",
            "HostKeyMismatch:Changed",
            "HostKeyMismatch:Unverified",
            "HostKeyMismatch:AlgorithmNotOffered",
            "AuthenticationRefused",
            "ConnectionFailed:Refused",
            "ConnectionFailed:Negotiation",
            "ConnectionFailed:Handshake",
            "ConnectionFailed:NameNotResolved",
            "TimedOut:Connect",
            "TimedOut:ServerUnresponsive",
            "TimedOut:Deadline",
            "OutputOverBound:Stdout",
            "OutputOverBound:Stderr",
            "Uncertain:AmbiguousResponse",
            "Uncertain:ConnectionLost",
        ],
    );
}
