//! Tests for the management key (M16D; VM-W41, VM part §4.5): the key comment, the rendered
//! `ssh-keygen` argv, the strict `.pub` parser and the credential derivation, and whole
//! generations through an in-process port that writes the key files itself, ending in
//! `render_invocation`. Nothing here runs `ssh-keygen`; the process port's own tests are in
//! `tests_keygen_process`.

use std::collections::BTreeSet;

use super::fakes::{
    concat, ecdsa_blob, ed25519_blob, exited, launch_command, mgmt_key, rsa_blob, ssh_string,
    Scratch, World, PUBLISHED_ED25519, PUBLISHED_ED25519_SHA256,
};
use super::invocation::{render_invocation, SshLimits, SshRenderRefusal};
use super::keygen::{
    generate_management_key, KeyComment, KeyCommentRefusal, KeyFile, KeygenInvocation, KeygenPort,
    KeygenRefusal, ManagementPublicKey, PublicKeyProblem, MANAGEMENT_KEY_DOMAIN,
    MAX_KEY_COMMENT_BYTES, MAX_PUBLIC_KEY_BYTES, SSH_KEYGEN_PROGRAM,
};
use super::known_hosts::KnownHostsFile;
use super::outcome::{SshOutput, SshTermination};
use super::path::{SshFilePath, SshPathRefusal, MAX_SSH_PATH_BYTES};
use super::protection::check_identity_file;
use super::wire::{base64_decode, base64_encode, openssh_sha256, KeyBlobProblem};
use crate::foundation::ids::DigestBuilder;
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::remote::{
    HostKey, HostKeyAlgorithm, HostKeyFingerprint, ManagementAction, ManagementIdentity,
    RemoteAccountName, RemoteInvocation, RemoteShellKind,
};

const COMMENT: &str = "yougori-mgmt.host-1";

fn comment() -> KeyComment {
    KeyComment::new(COMMENT).unwrap()
}

/// The `.pub` line `ssh-keygen` writes for `blob` and `comment`.
fn line(blob: &[u8], comment: &str) -> String {
    format!("ssh-ed25519 {} {comment}\n", base64_encode(blob))
}

fn parse(text: &str) -> Result<ManagementPublicKey, PublicKeyProblem> {
    ManagementPublicKey::parse(text.as_bytes(), &comment())
}

/// The handle the module notes promise for `blob`.
fn expected_credential(blob: &[u8]) -> CredentialRef {
    CredentialRef::from_digest(
        DigestBuilder::new(MANAGEMENT_KEY_DOMAIN)
            .bytes(blob)
            .finish(),
    )
}

/// What the in-process port does when run.
enum Act {
    /// Writes a private key file and the `.pub` line for the test blob of this seed.
    Generate(u8),
    /// Writes a private key file and this exact `.pub` text.
    WritePublic(String),
    /// Exits with 0 and writes nothing.
    Nothing,
    /// Exits with this code and writes nothing.
    Fail(i32),
}

/// A port that records every argv and writes the key files itself, as `ssh-keygen` would.
struct WritingPort {
    act: Act,
    argvs: Vec<Vec<String>>,
}

impl WritingPort {
    fn new(act: Act) -> Self {
        Self {
            act,
            argvs: Vec::new(),
        }
    }
}

impl KeygenPort for WritingPort {
    fn run(&mut self, invocation: &KeygenInvocation) -> SshOutput {
        self.argvs.push(invocation.argv().to_vec());
        let public = match &self.act {
            Act::Generate(seed) => line(&ed25519_blob(*seed), invocation.comment().as_str()),
            Act::WritePublic(text) => text.clone(),
            Act::Nothing => return exited(0, ""),
            Act::Fail(code) => return exited(*code, "ssh-keygen: failed\n"),
        };
        std::fs::write(invocation.private_key().as_path(), b"test private key").unwrap();
        std::fs::write(invocation.public_key().as_path(), public).unwrap();
        exited(0, "")
    }
}

#[test]
fn a_key_comment_is_one_plain_word() {
    let longest = "a".repeat(MAX_KEY_COMMENT_BYTES);
    for text in [
        COMMENT,
        "a",
        "7",
        "ops+mgmt@yougori.example",
        "a_b-c.d",
        &longest,
    ] {
        assert_eq!(KeyComment::new(text).unwrap().as_str(), text);
    }
    assert_eq!(KeyComment::new(""), Err(KeyCommentRefusal::Empty));
    assert_eq!(
        KeyComment::new("a".repeat(MAX_KEY_COMMENT_BYTES + 1)),
        Err(KeyCommentRefusal::TooLong { max_bytes: 64 })
    );
    for (text, character) in [
        ("two words", ' '),
        ("tab\there", '\t'),
        ("line\nbreak", '\n'),
        ("quote\"d", '"'),
        ("back\\slash", '\\'),
        ("semi;colon", ';'),
        ("dollar$(id)", '$'),
        ("percent%h", '%'),
        ("caf\u{e9}", '\u{e9}'),
    ] {
        assert_eq!(
            KeyComment::new(text),
            Err(KeyCommentRefusal::InvalidCharacter { character }),
            "{text:?}"
        );
    }
    for text in ["-C", ".hidden", "@host", "+x", "_x"] {
        assert_eq!(
            KeyComment::new(text),
            Err(KeyCommentRefusal::InvalidStart),
            "{text:?}"
        );
    }
    assert_eq!(serde_json::to_value(comment()).unwrap(), COMMENT);
}

#[test]
fn the_keygen_argv_is_exactly_the_rendered_form() {
    let scratch = Scratch::new();
    let path = scratch.path("id_ed25519");
    let invocation = KeygenInvocation::new(comment(), path.clone(), SshLimits::STANDARD).unwrap();
    assert_eq!(
        invocation.argv(),
        [
            SSH_KEYGEN_PROGRAM,
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            COMMENT,
            "-f",
            path.as_str()
        ]
    );
    assert_eq!(SSH_KEYGEN_PROGRAM, "ssh-keygen");
    assert_eq!(invocation.arguments(), &invocation.argv()[1..]);
    assert_eq!(invocation.private_key(), &path);
    assert_eq!(invocation.public_key().as_str(), format!("{path}.pub"));
    assert_eq!(invocation.comment(), &comment());
    assert_eq!(invocation.limits(), SshLimits::STANDARD);

    // A path that fits only without `.pub` is refused before anything runs.
    let root = if cfg!(windows) { "C:/" } else { "/" };
    let long = format!("{root}{}", "k".repeat(MAX_SSH_PATH_BYTES - root.len() - 2));
    let long = SshFilePath::new(long).unwrap();
    assert_eq!(
        KeygenInvocation::new(comment(), long, SshLimits::STANDARD),
        Err(KeygenRefusal::PublicKeyPath {
            refusal: SshPathRefusal::TooLong { max_bytes: 1_024 }
        })
    );
}

#[test]
fn a_public_key_line_parses_to_its_blob_comment_and_published_fingerprint() {
    // GitHub's published Ed25519 key and fingerprint, as a known answer.
    let text = format!("ssh-ed25519 {PUBLISHED_ED25519} {COMMENT}\n");
    let key = parse(&text).unwrap();
    assert_eq!(key.blob(), base64_decode(PUBLISHED_ED25519).unwrap());
    assert_eq!(key.comment(), &comment());
    assert_eq!(key.openssh_fingerprint(), PUBLISHED_ED25519_SHA256);
    assert_eq!(key.authorized_keys_line(), text.trim_end_matches('\n'));
    assert!(!key.authorized_keys_line().contains(['\n', '\r']));
    // A CRLF ending reads the same.
    let crlf = text.replace('\n', "\r\n");
    assert_eq!(parse(&crlf).unwrap(), key);
}

#[test]
fn the_credential_is_a_domain_separated_digest_of_the_blob_stable_and_distinct() {
    let one = parse(&line(&ed25519_blob(1), COMMENT)).unwrap();
    let again = parse(&line(&ed25519_blob(1), COMMENT)).unwrap();
    let other_comment = KeyComment::new("another-comment").unwrap();
    let relabelled = ManagementPublicKey::parse(
        line(&ed25519_blob(1), other_comment.as_str()).as_bytes(),
        &other_comment,
    )
    .unwrap();
    let two = parse(&line(&ed25519_blob(2), COMMENT)).unwrap();

    // Stable: the same key, read again or with another comment, has the same handle.
    assert_eq!(one.credential(), again.credential());
    assert_eq!(one.credential(), relabelled.credential());
    assert_eq!(one.credential(), expected_credential(&ed25519_blob(1)));
    // Distinct: another key, and the same bytes under other domains, differ.
    assert_ne!(one.credential(), two.credential());
    assert_eq!(two.credential(), expected_credential(&ed25519_blob(2)));
    assert_ne!(MANAGEMENT_KEY_DOMAIN, HostKeyFingerprint::DOMAIN);
    let as_host_key = HostKey::new(HostKeyAlgorithm::Ed25519, ed25519_blob(1)).unwrap();
    assert_ne!(
        one.credential().digest(),
        *as_host_key.fingerprint().digest()
    );
    assert_ne!(one.credential(), mgmt_key());
    // The fingerprint is OpenSSH's, over the same blob.
    assert_eq!(one.openssh_fingerprint(), openssh_sha256(&ed25519_blob(1)));
    assert_ne!(one.openssh_fingerprint(), two.openssh_fingerprint());
}

#[test]
fn a_malformed_public_key_file_is_refused() {
    let good = line(&ed25519_blob(1), COMMENT);
    let encoded = base64_encode(&ed25519_blob(1));
    let short_key = concat(&[ssh_string(b"ssh-ed25519"), ssh_string(&[1; 31])]);
    let trailing = concat(&[ed25519_blob(1), vec![0]]);
    let cases: Vec<(Vec<u8>, PublicKeyProblem)> = vec![
        (Vec::new(), PublicKeyProblem::Empty),
        (
            vec![b'a'; MAX_PUBLIC_KEY_BYTES + 1],
            PublicKeyProblem::TooLarge { max_bytes: 1_024 },
        ),
        (
            format!("ssh-ed25519 {encoded} caf\u{e9}\n").into_bytes(),
            PublicKeyProblem::NotAscii,
        ),
        (vec![0xff, b'\n'], PublicKeyProblem::NotAscii),
        (
            good.trim_end().as_bytes().to_vec(),
            PublicKeyProblem::NoFinalNewline,
        ),
        (
            format!("{good}{good}").into_bytes(),
            PublicKeyProblem::MoreThanOneLine,
        ),
        (
            format!("ssh-ed25519\t{encoded} {COMMENT}\n").into_bytes(),
            PublicKeyProblem::ControlCharacter,
        ),
        (
            format!("ssh-ed25519 {encoded} {COMMENT}\r\r\n").into_bytes(),
            PublicKeyProblem::ControlCharacter,
        ),
        (
            format!("ssh-ed25519 {encoded}\n").into_bytes(),
            PublicKeyProblem::FieldCount { fields: 2 },
        ),
        (
            format!("ssh-ed25519 {encoded} {COMMENT} extra\n").into_bytes(),
            PublicKeyProblem::FieldCount { fields: 4 },
        ),
        (
            format!("ssh-ed25519  {encoded} {COMMENT}\n").into_bytes(),
            PublicKeyProblem::FieldCount { fields: 4 },
        ),
        (
            format!(" {good}").into_bytes(),
            PublicKeyProblem::FieldCount { fields: 4 },
        ),
        (b"\n".to_vec(), PublicKeyProblem::FieldCount { fields: 1 }),
        (
            line(&rsa_blob(2_048, 1), COMMENT)
                .replacen("ssh-ed25519", "ssh-rsa", 1)
                .into_bytes(),
            PublicKeyProblem::KeyType,
        ),
        (
            good.replacen("ssh-ed25519", "ssh-ed448", 1).into_bytes(),
            PublicKeyProblem::KeyType,
        ),
        (
            format!("ssh-ed25519 not*base64 {COMMENT}\n").into_bytes(),
            PublicKeyProblem::Base64,
        ),
        // The last group of the blob is `AQEB`; `AQF=` sets bits past the last byte.
        (
            format!(
                "ssh-ed25519 {}AQF= {COMMENT}\n",
                &encoded[..encoded.len() - 4]
            )
            .into_bytes(),
            PublicKeyProblem::Base64,
        ),
        (
            line(&ecdsa_blob(HostKeyAlgorithm::EcdsaNistp256, 1), COMMENT).into_bytes(),
            PublicKeyProblem::KeyBlob {
                blob: KeyBlobProblem::KeyTypeMismatch,
            },
        ),
        (
            line(&short_key, COMMENT).into_bytes(),
            PublicKeyProblem::KeyBlob {
                blob: KeyBlobProblem::PublicValue,
            },
        ),
        (
            line(&trailing, COMMENT).into_bytes(),
            PublicKeyProblem::KeyBlob {
                blob: KeyBlobProblem::TrailingBytes,
            },
        ),
        (
            format!("ssh-ed25519 AAAA {COMMENT}\n").into_bytes(),
            PublicKeyProblem::KeyBlob {
                blob: KeyBlobProblem::Truncated,
            },
        ),
        (
            line(&ed25519_blob(1), "another-comment").into_bytes(),
            PublicKeyProblem::CommentMismatch,
        ),
        (
            line(&ed25519_blob(1), "YOUGORI-MGMT.HOST-1").into_bytes(),
            PublicKeyProblem::CommentMismatch,
        ),
    ];
    for (text, problem) in cases {
        assert_eq!(
            ManagementPublicKey::parse(&text, &comment()),
            Err(problem),
            "{:?}",
            String::from_utf8_lossy(&text)
        );
    }
    assert!(parse(&good).is_ok());
}

#[test]
fn a_generation_runs_once_protects_the_private_key_and_reads_the_public_key_back() {
    let scratch = Scratch::new();
    let invocation =
        KeygenInvocation::new(comment(), scratch.path("id_ed25519"), SshLimits::STANDARD).unwrap();
    let mut port = WritingPort::new(Act::Generate(5));
    let generated = generate_management_key(&mut port, &invocation).unwrap();
    assert_eq!(port.argvs, [invocation.argv().to_vec()]);

    let blob = ed25519_blob(5);
    assert_eq!(generated.identity_file().path(), invocation.private_key());
    assert_eq!(generated.credential(), expected_credential(&blob));
    assert_eq!(
        generated.identity_file().credential(),
        generated.public_key().credential()
    );
    assert_eq!(
        generated.authorized_keys_line(),
        format!("ssh-ed25519 {} {COMMENT}", base64_encode(&blob))
    );
    assert_eq!(generated.openssh_fingerprint(), openssh_sha256(&blob));
    assert_eq!(generated.public_key().blob(), blob);
    assert_eq!(check_identity_file(invocation.private_key()), Ok(()));
}

#[test]
fn an_existing_key_path_is_refused_before_the_port_runs() {
    for (file, as_directory) in [
        (KeyFile::Private, false),
        (KeyFile::Public, false),
        (KeyFile::Private, true),
    ] {
        let scratch = Scratch::new();
        let invocation =
            KeygenInvocation::new(comment(), scratch.path("id_ed25519"), SshLimits::STANDARD)
                .unwrap();
        let existing = match file {
            KeyFile::Private => invocation.private_key(),
            KeyFile::Public => invocation.public_key(),
        };
        if as_directory {
            std::fs::create_dir(existing.as_path()).unwrap();
        } else {
            std::fs::write(existing.as_path(), b"someone else's").unwrap();
        }
        let mut port = WritingPort::new(Act::Generate(5));
        assert_eq!(
            generate_management_key(&mut port, &invocation),
            Err(KeygenRefusal::TargetExists { file }),
            "{file:?} {as_directory}"
        );
        assert!(port.argvs.is_empty());
        if !as_directory {
            assert_eq!(
                std::fs::read(existing.as_path()).unwrap(),
                b"someone else's"
            );
        }
    }
}

#[test]
fn a_failed_incomplete_or_malformed_run_is_refused() {
    let run = |act: Act| {
        let scratch = Scratch::new();
        let invocation =
            KeygenInvocation::new(comment(), scratch.path("id_ed25519"), SshLimits::STANDARD)
                .unwrap();
        let result = generate_management_key(&mut WritingPort::new(act), &invocation);
        // The private key file, where one was written, is owner-only whatever came after.
        if invocation.private_key().as_path().exists() {
            assert_eq!(check_identity_file(invocation.private_key()), Ok(()));
        }
        result
    };
    assert_eq!(
        run(Act::Fail(1)),
        Err(KeygenRefusal::Failed {
            termination: SshTermination::Exited { code: 1 },
            stderr: "ssh-keygen: failed\n".to_owned(),
        })
    );
    assert_eq!(
        run(Act::Nothing),
        Err(KeygenRefusal::KeyFileNotWritten {
            file: KeyFile::Private
        })
    );
    assert_eq!(
        run(Act::WritePublic(format!("ssh-ed25519 AAAA {COMMENT}\n"))),
        Err(KeygenRefusal::PublicKey {
            problem: PublicKeyProblem::KeyBlob {
                blob: KeyBlobProblem::Truncated
            }
        })
    );
    assert_eq!(
        run(Act::WritePublic(line(&ed25519_blob(5), "another-comment"))),
        Err(KeygenRefusal::PublicKey {
            problem: PublicKeyProblem::CommentMismatch
        })
    );
    assert_eq!(
        run(Act::WritePublic(String::new())),
        Err(KeygenRefusal::PublicKey {
            problem: PublicKeyProblem::Empty
        })
    );
    let json = serde_json::to_value(KeygenRefusal::TargetExists {
        file: KeyFile::Public,
    })
    .unwrap();
    assert_eq!(json["kind"], "target_exists");
    assert_eq!(json["file"], "public");
}

#[test]
fn a_generated_key_feeds_render_invocation_as_the_identity_file() {
    let scratch = Scratch::new();
    let invocation =
        KeygenInvocation::new(comment(), scratch.path("id_ed25519"), SshLimits::STANDARD).unwrap();
    let generated =
        generate_management_key(&mut WritingPort::new(Act::Generate(9)), &invocation).unwrap();

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
        KnownHostsFile::write(world.key.clone(), scratch.path("known_hosts")).unwrap();
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
        SshLimits::STANDARD,
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
    assert_eq!(
        rendered.argv().iter().filter(|word| *word == "-i").count(),
        1
    );

    // An identity that names another client key does not get this file.
    assert_eq!(
        render_invocation(
            &world.identity,
            &world.known,
            &known_hosts,
            generated.identity_file(),
            SshLimits::STANDARD,
            &world.launch(),
        )
        .map(|_| ()),
        Err(SshRenderRefusal::IdentityFileForAnotherKey)
    );
}
