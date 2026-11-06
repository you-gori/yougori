//! Tests for the `ssh-keygen` process port, with this test executable as the program (see
//! `fake_keygen`): what it is started with and from where, a refused existing target,
//! failed, unstartable and malformed runs, and a generated key feeding `render_invocation`
//! and reaching the fake client as its identity file. Nothing here runs `ssh-keygen` or
//! `ssh`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::fake_client::{Record, Script, RECORD_FILE, SCRIPT_FILE};
use super::fake_keygen::{
    public_line, KeygenScript, FAKE_PRIVATE_KEY, KEYGEN_RECORD_FILE, KEYGEN_SCRIPT_FILE,
};
use super::fakes::{ed25519_blob, launch_command, Scratch, World};
use super::invocation::{render_invocation, SshLimits, SshRenderRefusal};
use super::keygen::{
    generate_management_key, KeyComment, KeyFile, KeygenInvocation, KeygenRefusal,
    ManagementPublicKey, ProcessKeygenPort, PublicKeyProblem,
};
use super::known_hosts::KnownHostsFile;
use super::outcome::{SshOutcome, SshTermination};
use super::process::{ProcessSshPort, SshClientRefusal, CLIENT_ENVIRONMENT, NONE_ENTRY};
use super::protection::check_identity_file;
use super::wire::{base64_encode, openssh_sha256, KeyBlobProblem};
use crate::sandbox_contract::remote::{
    ManagementAction, ManagementIdentity, RemoteAccountName, RemoteInvocation, RemoteShellKind,
};

const COMMENT: &str = "yougori-mgmt.host-1";

/// This test executable, the fake `ssh-keygen` and the fake client.
fn program() -> PathBuf {
    std::env::current_exe().unwrap()
}

/// Limits with room for a whole test executable to start, even on a loaded machine.
fn patient() -> SshLimits {
    SshLimits::new(10, 10, 2, Duration::from_secs(60), 64 * 1024, 64 * 1024).unwrap()
}

fn comment() -> KeyComment {
    KeyComment::new(COMMENT).unwrap()
}

/// A working directory for the program and a separate directory for the keys.
struct Bench {
    work: tempfile::TempDir,
    keys: Scratch,
}

impl Bench {
    fn new() -> Self {
        Self {
            work: tempfile::Builder::new()
                .prefix("remote-ssh-keygen-")
                .tempdir()
                .unwrap(),
            keys: Scratch::new(),
        }
    }

    fn work(&self) -> &Path {
        self.work.path()
    }

    fn port(&self) -> ProcessKeygenPort {
        ProcessKeygenPort::new(program(), self.work()).unwrap()
    }

    fn script(&self, script: &KeygenScript) {
        std::fs::write(
            self.work().join(KEYGEN_SCRIPT_FILE),
            serde_json::to_vec(script).unwrap(),
        )
        .unwrap();
    }

    fn record(&self) -> Record {
        serde_json::from_slice(&std::fs::read(self.work().join(KEYGEN_RECORD_FILE)).unwrap())
            .unwrap()
    }

    fn has_record(&self) -> bool {
        self.work().join(KEYGEN_RECORD_FILE).exists()
    }

    fn invocation(&self) -> KeygenInvocation {
        KeygenInvocation::new(comment(), self.keys.path("id_ed25519"), patient()).unwrap()
    }
}

#[test]
fn the_keygen_is_started_with_exactly_the_rendered_arguments_and_a_cleared_environment() {
    let bench = Bench::new();
    let invocation = bench.invocation();
    bench.script(&KeygenScript::Generate { seed: 7 });
    let mut port = bench.port();
    assert_eq!(port.program(), program().as_path());
    assert_eq!(port.working_directory(), bench.work());
    let generated = generate_management_key(&mut port, &invocation).unwrap();
    assert_eq!(port.last_refusal(), None);

    let record = bench.record();
    // The rendered program name is replaced by the configured path; the rest is exact,
    // `-N` followed by an empty word.
    assert_eq!(PathBuf::from(&record.program), program());
    let path = invocation.private_key().as_str();
    assert_eq!(
        record.arguments,
        ["-q", "-t", "ed25519", "-N", "", "-C", COMMENT, "-f", path]
    );
    assert_eq!(record.arguments, invocation.arguments());
    let expected: BTreeMap<String, String> = CLIENT_ENVIRONMENT
        .iter()
        .filter_map(|name| Some(((*name).to_owned(), std::env::var(name).ok()?)))
        .collect();
    assert_eq!(record.environment, expected);
    assert_eq!(
        record.environment.keys().collect::<Vec<_>>(),
        ["ProgramData", "SystemRoot"]
    );
    assert!(record.stdin.is_empty());
    assert_eq!(
        std::fs::canonicalize(&record.working_directory).unwrap(),
        std::fs::canonicalize(bench.work()).unwrap()
    );

    // What the fake wrote: the key read back from `.pub`, the private key protected.
    let blob = ed25519_blob(7);
    assert_eq!(
        generated.authorized_keys_line(),
        format!("ssh-ed25519 {} {COMMENT}", base64_encode(&blob))
    );
    assert_eq!(generated.openssh_fingerprint(), openssh_sha256(&blob));
    let parsed = ManagementPublicKey::parse(public_line(7, COMMENT).as_bytes(), &comment());
    assert_eq!(generated.credential(), parsed.unwrap().credential());
    assert_eq!(generated.identity_file().path(), invocation.private_key());
    assert_eq!(check_identity_file(invocation.private_key()), Ok(()));
    // The test reads the fake's bytes back; the engine never reads the private key.
    assert_eq!(
        std::fs::read(invocation.private_key().as_path()).unwrap(),
        FAKE_PRIVATE_KEY
    );
}

#[test]
fn an_existing_target_is_refused_before_the_keygen_starts() {
    for (file, as_directory) in [
        (KeyFile::Private, false),
        (KeyFile::Public, false),
        (KeyFile::Private, true),
    ] {
        let bench = Bench::new();
        let invocation = bench.invocation();
        let existing = match file {
            KeyFile::Private => invocation.private_key(),
            KeyFile::Public => invocation.public_key(),
        };
        if as_directory {
            std::fs::create_dir(existing.as_path()).unwrap();
        } else {
            std::fs::write(existing.as_path(), b"someone else's").unwrap();
        }
        bench.script(&KeygenScript::Generate { seed: 7 });
        let mut port = bench.port();
        assert_eq!(
            generate_management_key(&mut port, &invocation),
            Err(KeygenRefusal::TargetExists { file }),
            "{file:?} {as_directory}"
        );
        // The program never started.
        assert!(!bench.has_record());
        assert_eq!(port.last_refusal(), None);
        if !as_directory {
            assert_eq!(
                std::fs::read(existing.as_path()).unwrap(),
                b"someone else's"
            );
        }
    }
}

#[test]
fn a_failed_unstartable_incomplete_or_malformed_run_is_refused() {
    // The program fails.
    let bench = Bench::new();
    let invocation = bench.invocation();
    let stderr = "Saving key failed: Permission denied\r\n";
    bench.script(&KeygenScript::Fail {
        stderr: stderr.to_owned(),
        code: 1,
    });
    assert_eq!(
        generate_management_key(&mut bench.port(), &invocation),
        Err(KeygenRefusal::Failed {
            termination: SshTermination::Exited { code: 1 },
            stderr: stderr.to_owned(),
        })
    );
    assert!(bench.has_record());
    assert!(!invocation.private_key().as_path().exists());

    // The program does not exist, or the working directory no longer qualifies.
    let bench = Bench::new();
    let invocation = bench.invocation();
    bench.script(&KeygenScript::Generate { seed: 7 });
    let missing = bench.work().join("no-such-ssh-keygen.exe");
    let mut port = ProcessKeygenPort::new(&missing, bench.work()).unwrap();
    let not_started = Err(KeygenRefusal::Failed {
        termination: SshTermination::NotStarted,
        stderr: String::new(),
    });
    assert_eq!(generate_management_key(&mut port, &invocation), not_started);
    assert!(matches!(
        port.last_refusal(),
        Some(SshClientRefusal::StartFailed { .. })
    ));
    let mut port = bench.port();
    std::fs::write(bench.work().join(NONE_ENTRY), b"").unwrap();
    assert_eq!(generate_management_key(&mut port, &invocation), not_started);
    assert_eq!(
        port.last_refusal(),
        Some(&SshClientRefusal::NoneEntryInWorkingDirectory)
    );
    assert!(!bench.has_record());
    assert_eq!(
        ProcessKeygenPort::new("ssh-keygen.exe", bench.keys.path("k").as_path()).map(|_| ()),
        Err(SshClientRefusal::ProgramNotAbsolute)
    );

    // The program reports success without writing the keys.
    let bench = Bench::new();
    bench.script(&KeygenScript::ExitWithoutFiles);
    assert_eq!(
        generate_management_key(&mut bench.port(), &bench.invocation()),
        Err(KeygenRefusal::KeyFileNotWritten {
            file: KeyFile::Private
        })
    );

    // The `.pub` is malformed or carries another comment; the private key file was
    // protected before it was read.
    for (public, problem) in [
        (
            format!("ssh-ed25519 AAAA {COMMENT}\n"),
            PublicKeyProblem::KeyBlob {
                blob: KeyBlobProblem::Truncated,
            },
        ),
        (
            public_line(3, "another-comment"),
            PublicKeyProblem::CommentMismatch,
        ),
        (
            format!("{}{}", public_line(3, COMMENT), public_line(4, COMMENT)),
            PublicKeyProblem::MoreThanOneLine,
        ),
    ] {
        let bench = Bench::new();
        let invocation = bench.invocation();
        bench.script(&KeygenScript::WritePublic { public });
        assert_eq!(
            generate_management_key(&mut bench.port(), &invocation),
            Err(KeygenRefusal::PublicKey { problem })
        );
        assert_eq!(check_identity_file(invocation.private_key()), Ok(()));
    }
}

#[test]
fn a_generated_key_feeds_render_invocation_and_reaches_the_client_as_its_identity_file() {
    let bench = Bench::new();
    let invocation = bench.invocation();
    bench.script(&KeygenScript::Generate { seed: 9 });
    let generated = generate_management_key(&mut bench.port(), &invocation).unwrap();

    let world = World::standard();
    let identity = ManagementIdentity::new(
        &world.enrollment,
        RemoteAccountName::new("yougori").unwrap(),
        generated.credential(),
        RemoteShellKind::Posix,
        ManagementAction::ALL
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
    )
    .unwrap();
    let known_hosts =
        KnownHostsFile::write(world.key.clone(), bench.keys.path("known_hosts")).unwrap();
    let launch = RemoteInvocation::new(
        &identity,
        &world.known,
        ManagementAction::LaunchVm,
        world.shell(),
        &launch_command(),
    )
    .unwrap();
    let rendered = render_invocation(
        &identity,
        &world.known,
        &known_hosts,
        generated.identity_file(),
        patient(),
        &launch,
    )
    .unwrap();
    assert_eq!(rendered.identity_file(), invocation.private_key());
    let at = rendered
        .argv()
        .iter()
        .position(|word| word == "-i")
        .unwrap();
    assert_eq!(rendered.argv()[at + 1], invocation.private_key().as_str());

    // The fake client, started from the same working directory, is handed that path.
    std::fs::write(
        bench.work().join(SCRIPT_FILE),
        serde_json::to_vec(&Script::Exit {
            stdout: String::new(),
            stderr: String::new(),
            code: 0,
        })
        .unwrap(),
    )
    .unwrap();
    let mut client = ProcessSshPort::new(program(), bench.work()).unwrap();
    let run = rendered.run(&mut client);
    assert_eq!(run.outcome, SshOutcome::RemoteExit { code: 0 });
    let record: Record =
        serde_json::from_slice(&std::fs::read(bench.work().join(RECORD_FILE)).unwrap()).unwrap();
    assert_eq!(record.arguments, rendered.arguments());
    assert!(record
        .arguments
        .windows(2)
        .any(|pair| pair == ["-i", invocation.private_key().as_str()]));

    // An identity that names another client key does not get this file.
    assert_eq!(
        render_invocation(
            &world.identity,
            &world.known,
            &known_hosts,
            generated.identity_file(),
            patient(),
            &world.launch(),
        )
        .map(|_| ()),
        Err(SshRenderRefusal::IdentityFileForAnotherKey)
    );
}
