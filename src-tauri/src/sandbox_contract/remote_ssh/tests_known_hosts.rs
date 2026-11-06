//! Tests for the `known_hosts` rendering and its strict parser.

use super::fakes::{
    authority, blob_for, concat, ecdsa_blob, ed25519_blob, host_id, rsa_blob, ssh_string, Scratch,
    World, PUBLISHED_ED25519, PUBLISHED_ED25519_SHA256,
};
use super::known_hosts::{
    parse_known_hosts, EnrolledHostKey, KnownHostsFile, KnownHostsProblem, KnownHostsRefusal,
    SshTarget,
};
use super::wire::{
    base64_decode, base64_encode, check_blob, known_hosts_key_type, openssh_sha256, KeyBlobProblem,
    MIN_RSA_MODULUS_BITS,
};
use crate::foundation::ids::MonotonicTime;
use crate::sandbox_contract::remote::{
    EnrollmentEvidence, EnrollmentPolicy, HostKey, HostKeyAlgorithm, HostKeyProblem, HostKeyRefusal,
};

const ALGORITHMS: [HostKeyAlgorithm; 4] = [
    HostKeyAlgorithm::Ed25519,
    HostKeyAlgorithm::EcdsaNistp256,
    HostKeyAlgorithm::EcdsaNistp384,
    HostKeyAlgorithm::RsaSha2_512,
];

#[test]
fn base64_matches_rfc_4648_and_refuses_every_other_spelling() {
    for (plain, encoded) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64_encode(plain.as_bytes()), encoded);
        if !encoded.is_empty() {
            assert_eq!(base64_decode(encoded).unwrap(), plain.as_bytes());
        }
    }
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(base64_decode(&base64_encode(&all)).unwrap(), all);
    for bad in [
        "",
        "Zg",
        "Zg=",
        "Zh==",
        "Zm9=",
        "Z===",
        "Zg==Zg==",
        "Zm9v\n",
        "Zm9v YmFy",
        "Zm-v",
        "Zm_v",
        "=Zm9",
        "Zm9v====",
    ] {
        assert_eq!(base64_decode(bad), None, "{bad:?}");
    }
}

#[test]
fn a_published_ed25519_key_round_trips_with_its_openssh_fingerprint() {
    let blob = base64_decode(PUBLISHED_ED25519).unwrap();
    assert_eq!(check_blob(HostKeyAlgorithm::Ed25519, &blob), Ok(()));
    assert_eq!(base64_encode(&blob), PUBLISHED_ED25519);
    assert_eq!(openssh_sha256(&blob), PUBLISHED_ED25519_SHA256);
    let world = World::new("203.0.113.7:2222", HostKeyAlgorithm::Ed25519, blob);
    assert_eq!(
        world.key.known_hosts_line(),
        format!("[203.0.113.7]:2222 ssh-ed25519 {PUBLISHED_ED25519}\n")
    );
    assert_eq!(world.key.openssh_fingerprint(), PUBLISHED_ED25519_SHA256);
    assert_eq!(world.key.enrollment(), &world.enrollment);
}

#[test]
fn the_host_is_bracketed_with_its_port_only_off_port_22() {
    let encoded = base64_encode(&ed25519_blob(1));
    for (address, pattern, command_host) in [
        ("mgmt.example.net", "mgmt.example.net", "mgmt.example.net"),
        (
            "MGMT.Example.NET:22",
            "mgmt.example.net",
            "mgmt.example.net",
        ),
        (
            "mgmt.example.net:2222",
            "[mgmt.example.net]:2222",
            "mgmt.example.net",
        ),
        ("203.0.113.7", "203.0.113.7", "203.0.113.7"),
        ("203.0.113.7:2222", "[203.0.113.7]:2222", "203.0.113.7"),
        ("[2001:db8::7]", "2001:db8::7", "2001:db8::7"),
        ("[2001:db8::7]:2222", "[2001:db8::7]:2222", "2001:db8::7"),
    ] {
        let world = World::new(address, HostKeyAlgorithm::Ed25519, ed25519_blob(1));
        let target = world.key.target();
        assert_eq!(target.known_hosts_pattern(), pattern, "{address}");
        assert_eq!(target.command_host(), command_host, "{address}");
        let line = world.key.known_hosts_line();
        assert_eq!(line, format!("{pattern} ssh-ed25519 {encoded}\n"));
        assert_eq!(
            parse_known_hosts(line.as_bytes(), &world.known, target),
            Ok(world.key.clone())
        );
    }
}

#[test]
fn every_algorithm_renders_its_key_type_and_round_trips() {
    for algorithm in ALGORITHMS {
        let world = World::new("mgmt.example.net:2200", algorithm, blob_for(algorithm, 3));
        let line = world.key.known_hosts_line();
        let key_type = known_hosts_key_type(algorithm);
        assert!(
            line.starts_with(&format!("[mgmt.example.net]:2200 {key_type} AAAA")),
            "{line}"
        );
        assert_eq!(line.matches('\n').count(), 1);
        let parsed = parse_known_hosts(line.as_bytes(), &world.known, world.key.target()).unwrap();
        assert_eq!(parsed, world.key);
        assert_eq!(parsed.algorithm(), algorithm);
        assert_eq!(
            parsed.host_key().fingerprint(),
            world.enrollment.fingerprint
        );
    }
    // RSA: the key format in the line, the signature algorithm for HostKeyAlgorithms.
    assert_eq!(
        known_hosts_key_type(HostKeyAlgorithm::RsaSha2_512),
        "ssh-rsa"
    );
    assert_eq!(HostKeyAlgorithm::RsaSha2_512.tag(), "rsa-sha2-512");
}

#[test]
fn malformed_key_blobs_are_refused() {
    use HostKeyAlgorithm::{EcdsaNistp256, EcdsaNistp384, Ed25519, RsaSha2_512};
    let mut trailing = ed25519_blob(1);
    trailing.push(0);
    let mut truncated = ed25519_blob(1);
    truncated.pop();
    let mut compressed = ecdsa_blob(EcdsaNistp256, 1);
    let first_point_byte = compressed.len() - 65;
    compressed[first_point_byte] = 0x02;
    let rsa = |exponent: &[u8], modulus: &[u8]| {
        concat(&[
            ssh_string(b"ssh-rsa"),
            ssh_string(exponent),
            ssh_string(modulus),
        ])
    };
    let modulus: Vec<u8> = std::iter::once(0x00).chain([0xc5; 256]).collect();
    for (algorithm, blob, problem) in [
        (
            Ed25519,
            ecdsa_blob(EcdsaNistp256, 1),
            KeyBlobProblem::KeyTypeMismatch,
        ),
        (
            EcdsaNistp384,
            ecdsa_blob(EcdsaNistp256, 1),
            KeyBlobProblem::KeyTypeMismatch,
        ),
        (Ed25519, trailing, KeyBlobProblem::TrailingBytes),
        (Ed25519, truncated, KeyBlobProblem::Truncated),
        (Ed25519, vec![0, 0, 0], KeyBlobProblem::Truncated),
        (
            Ed25519,
            concat(&[ssh_string(b"ssh-ed25519"), ssh_string(&[1; 31])]),
            KeyBlobProblem::PublicValue,
        ),
        (
            EcdsaNistp256,
            concat(&[
                ssh_string(b"ecdsa-sha2-nistp256"),
                ssh_string(b"nistp384"),
                ssh_string(&[4; 65]),
            ]),
            KeyBlobProblem::CurveMismatch,
        ),
        (EcdsaNistp256, compressed, KeyBlobProblem::PublicValue),
        (
            RsaSha2_512,
            rsa_blob(1_024, 1),
            KeyBlobProblem::RsaModulusTooShort {
                bits: 1_024,
                min_bits: MIN_RSA_MODULUS_BITS,
            },
        ),
        (
            RsaSha2_512,
            rsa(&[0x00, 0x01], &modulus),
            KeyBlobProblem::RsaInteger,
        ),
        (
            RsaSha2_512,
            rsa(&[0x81], &modulus),
            KeyBlobProblem::RsaInteger,
        ),
        (RsaSha2_512, rsa(&[], &modulus), KeyBlobProblem::RsaInteger),
        (
            RsaSha2_512,
            rsa(&[3], &[0x00, 0x00, 0xc5]),
            KeyBlobProblem::RsaInteger,
        ),
    ] {
        assert_eq!(check_blob(algorithm, &blob), Err(problem), "{algorithm:?}");
    }
    assert_eq!(check_blob(RsaSha2_512, &rsa(&[3], &modulus)), Ok(()));

    let world = World::standard();
    let target = world.key.target().clone();
    assert_eq!(
        EnrolledHostKey::new(&world.known, target.clone(), Ed25519, Vec::new()),
        Err(KnownHostsRefusal::HostKey {
            problem: HostKeyProblem::Empty
        })
    );
    // V12's own fixtures enroll raw 32-byte keys; they are not wire-form blobs.
    assert_eq!(
        EnrolledHostKey::new(&world.known, target, Ed25519, vec![1; 32]),
        Err(KnownHostsRefusal::KeyBlob {
            problem: KeyBlobProblem::Truncated
        })
    );
}

#[test]
fn a_key_v12_does_not_accept_is_refused_with_v12s_own_refusal() {
    let world = World::standard();
    let target = world.key.target().clone();
    let presented = HostKey::new(HostKeyAlgorithm::Ed25519, ed25519_blob(2)).unwrap();
    assert_eq!(
        EnrolledHostKey::new(
            &world.known,
            target,
            HostKeyAlgorithm::Ed25519,
            ed25519_blob(2)
        ),
        Err(KnownHostsRefusal::Enrollment {
            refusal: HostKeyRefusal::Changed {
                host: host_id(1),
                enrolled: world.enrollment.fingerprint,
                presented: presented.fingerprint(),
            }
        })
    );
    let elsewhere = SshTarget::new(host_id(2), authority("203.0.113.8"));
    assert_eq!(
        EnrolledHostKey::new(
            &world.known,
            elsewhere,
            HostKeyAlgorithm::Ed25519,
            ed25519_blob(1)
        ),
        Err(KnownHostsRefusal::Enrollment {
            refusal: HostKeyRefusal::NotEnrolled { host: host_id(2) }
        })
    );
    // A line holding another key is refused the same way when parsed.
    let other = World::new(
        "203.0.113.7:2222",
        HostKeyAlgorithm::Ed25519,
        ed25519_blob(2),
    );
    assert!(matches!(
        parse_known_hosts(
            other.key.known_hosts_line().as_bytes(),
            &world.known,
            world.key.target()
        ),
        Err(KnownHostsRefusal::Enrollment {
            refusal: HostKeyRefusal::Changed { .. }
        })
    ));
}

#[test]
fn the_file_is_written_new_and_read_back_exactly() {
    let world = World::standard();
    let scratch = Scratch::new();
    let path = scratch.path("known_hosts");
    let file = KnownHostsFile::write(world.key.clone(), path.clone()).unwrap();
    assert_eq!(file.path(), &path);
    assert_eq!(
        std::fs::read(path.as_path()).unwrap(),
        world.key.known_hosts_line().into_bytes()
    );
    assert_eq!(file.read_back(&world.known), Ok(world.key.clone()));
    // An existing entry is never overwritten.
    assert_eq!(
        KnownHostsFile::write(world.key.clone(), path.clone()),
        Err(KnownHostsRefusal::PathExists)
    );
    std::fs::create_dir(scratch.path("a-directory").as_path()).unwrap();
    assert_eq!(
        KnownHostsFile::write(world.key.clone(), scratch.path("a-directory")),
        Err(KnownHostsRefusal::PathExists)
    );
    // An appended line, as OpenSSH's CheckHostIP would add, is refused on read-back.
    let mut tampered = world.key.known_hosts_line();
    tampered.push_str(&tampered.replace("[203.0.113.7]:2222", "203.0.113.9"));
    std::fs::write(path.as_path(), tampered).unwrap();
    assert_eq!(
        file.read_back(&world.known),
        Err(KnownHostsRefusal::NotRendered {
            problem: KnownHostsProblem::MoreThanOneLine
        })
    );
    std::fs::remove_file(path.as_path()).unwrap();
    assert!(matches!(
        file.read_back(&world.known),
        Err(KnownHostsRefusal::File { .. })
    ));
}

#[test]
fn the_parser_refuses_every_line_it_did_not_render() {
    let world = World::standard();
    let target = world.key.target();
    let line = world.key.known_hosts_line();
    let body = line.trim_end_matches('\n');
    let encoded = base64_encode(&ed25519_blob(1));
    let with = |problem| Err::<EnrolledHostKey, _>(KnownHostsRefusal::NotRendered { problem });
    use KnownHostsProblem as P;
    let cases: Vec<(String, P)> = vec![
        (String::new(), P::Empty),
        ("\n".into(), P::Empty),
        (body.into(), P::NoFinalNewline),
        (format!("{body}\r\n"), P::CarriageReturn),
        (format!("{line}{line}"), P::MoreThanOneLine),
        (format!("{line}\n"), P::MoreThanOneLine),
        (format!("# enrolled\n{line}"), P::MoreThanOneLine),
        ("# enrolled\n".into(), P::CommentLine),
        (format!("@cert-authority {line}"), P::Marker),
        (format!("@revoked {line}"), P::Marker),
        (
            format!("|1|c2FsdA==|aGFzaA== ssh-ed25519 {encoded}\n"),
            P::HashedHost,
        ),
        (format!("* ssh-ed25519 {encoded}\n"), P::HostPattern),
        (
            format!("[203.0.113.*]:2222 ssh-ed25519 {encoded}\n"),
            P::HostPattern,
        ),
        (
            format!("[203.0.113.?]:2222 ssh-ed25519 {encoded}\n"),
            P::HostPattern,
        ),
        (
            format!("!evil.example ssh-ed25519 {encoded}\n"),
            P::HostPattern,
        ),
        (
            format!("[203.0.113.7]:2222,203.0.113.7 ssh-ed25519 {encoded}\n"),
            P::HostPattern,
        ),
        (
            format!("{body} yougori@home\n"),
            P::FieldCount { fields: 4 },
        ),
        (format!("{body} \n"), P::FieldCount { fields: 4 }),
        (format!(" {line}"), P::FieldCount { fields: 4 }),
        (
            body.replacen(' ', "  ", 1) + "\n",
            P::FieldCount { fields: 4 },
        ),
        (body.replacen(' ', "\t", 1) + "\n", P::ControlCharacter),
        (
            "[203.0.113.7]:2222 ssh-ed25519\n".into(),
            P::FieldCount { fields: 2 },
        ),
        (
            format!("203.0.113.7:2222 ssh-ed25519 {encoded}\n"),
            P::WrongHost,
        ),
        (format!("203.0.113.7 ssh-ed25519 {encoded}\n"), P::WrongHost),
        (
            format!("[203.0.113.7]:22 ssh-ed25519 {encoded}\n"),
            P::WrongHost,
        ),
        (
            format!("[203.0.113.8]:2222 ssh-ed25519 {encoded}\n"),
            P::WrongHost,
        ),
        (
            format!("[203.0.113.7]:2223 ssh-ed25519 {encoded}\n"),
            P::WrongHost,
        ),
        (
            format!("[203.0.113.7]:2222 ssh-dss {encoded}\n"),
            P::UnsupportedKeyType,
        ),
        (
            format!("[203.0.113.7]:2222 SSH-ED25519 {encoded}\n"),
            P::UnsupportedKeyType,
        ),
        (
            format!("[203.0.113.7]:2222 rsa-sha2-512 {encoded}\n"),
            P::UnsupportedKeyType,
        ),
        (
            format!("[203.0.113.7]:2222 ssh-ed25519 {}\n", &encoded[1..]),
            P::Base64,
        ),
        (
            format!("[203.0.113.7]:2222 ssh-ed25519 {encoded}====\n"),
            P::Base64,
        ),
        ("[203.0.113.7]:2222 ssh-ed25519 ÄÖ\n".into(), P::NotAscii),
    ];
    for (text, problem) in cases {
        assert_eq!(
            parse_known_hosts(text.as_bytes(), &world.known, target),
            with(problem),
            "{text:?}"
        );
    }
    // Another key type over this key's blob.
    assert_eq!(
        parse_known_hosts(
            format!("[203.0.113.7]:2222 ecdsa-sha2-nistp256 {encoded}\n").as_bytes(),
            &world.known,
            target
        ),
        Err(KnownHostsRefusal::KeyBlob {
            problem: KeyBlobProblem::KeyTypeMismatch
        })
    );
    let oversized = vec![b'a'; super::known_hosts::MAX_KNOWN_HOSTS_BYTES + 1];
    assert!(matches!(
        parse_known_hosts(&oversized, &world.known, target),
        Err(KnownHostsRefusal::NotRendered {
            problem: KnownHostsProblem::TooLarge { .. }
        })
    ));
    assert_eq!(
        parse_known_hosts(&[0xff, b'\n'], &world.known, target),
        with(P::NotAscii)
    );
    // The rendered line itself is accepted.
    assert_eq!(
        parse_known_hosts(line.as_bytes(), &world.known, target),
        Ok(world.key.clone())
    );
}

#[test]
fn a_retired_or_re_enrolled_host_makes_the_rendered_key_stale() {
    let mut world = World::standard();
    let scratch = Scratch::new();
    let file = KnownHostsFile::write(world.key.clone(), scratch.path("known_hosts")).unwrap();
    world.known.retire(&host_id(1));
    assert_eq!(
        world.key.check_current(&world.known),
        Err(KnownHostsRefusal::Enrollment {
            refusal: HostKeyRefusal::NotEnrolled { host: host_id(1) }
        })
    );
    // Re-enrolled with the same key: a new generation, so the rendered file is stale.
    let same = HostKey::new(HostKeyAlgorithm::Ed25519, ed25519_blob(1)).unwrap();
    let again = world
        .known
        .enroll(
            host_id(1),
            &same,
            EnrollmentEvidence::InjectedAtProvisioning {
                injected: same.fingerprint(),
            },
            EnrollmentPolicy::default(),
            MonotonicTime::from_nanos(5),
        )
        .unwrap();
    let stale = Err(KnownHostsRefusal::StaleEnrollment {
        host: host_id(1),
        rendered: world.enrollment.generation,
        current: again.generation,
    });
    assert_eq!(world.key.check_current(&world.known), stale);
    assert_eq!(file.read_back(&world.known).map(|_| ()), stale);
}
