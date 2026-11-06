//! Tests for the `ssh` argv renderer, its typed inputs and the port hand-off.

use std::time::Duration;

use super::fakes::{
    authority, ed25519_blob, exited, files, helper, host_id, identity_for, launch_command,
    other_key, rsa_blob, FakeSshPort, Scratch, World,
};
use super::invocation::{
    render_invocation, IdentityFile, SshLimit, SshLimits, SshLimitsRefusal, SshRenderRefusal,
};
use super::known_hosts::{EnrolledHostKey, KnownHostsFile, KnownHostsRefusal, SshTarget};
use super::outcome::SshOutcome;
use super::path::{SshFilePath, SshPathRefusal, MAX_SSH_PATH_BYTES};
use crate::foundation::ids::MonotonicTime;
use crate::sandbox_contract::destinations::{Authority, DestinationPort};
use crate::sandbox_contract::provider::find_encoded;
use crate::sandbox_contract::remote::{
    replace_jupyter_password, EnrollmentEvidence, EnrollmentPolicy, ExecutionContext, HostKey,
    HostKeyAlgorithm, ManagementAction, ManagementRefusal, RemoteAccountName, RemoteInvocation,
    RemoteSecret,
};

const PASSWORD: &[u8] = b"correct-horse-battery-staple-42";

fn strings(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn a_typical_invocation_renders_the_exact_argv() {
    let world = World::standard();
    let scratch = Scratch::new();
    let (known_hosts, identity_file) = files(&world, &scratch);
    let invocation = world.launch();
    let rendered = render_invocation(
        &world.identity,
        &world.known,
        &known_hosts,
        &identity_file,
        SshLimits::STANDARD,
        &invocation,
    )
    .unwrap();
    let user_known_hosts = format!("UserKnownHostsFile={}", known_hosts.path());
    let expected = strings(&[
        "ssh",
        "-F",
        "none",
        "-o",
        &user_known_hosts,
        "-o",
        "GlobalKnownHostsFile=none",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "HostKeyAlgorithms=ssh-ed25519",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "CheckHostIP=no",
        "-o",
        "VerifyHostKeyDNS=no",
        "-o",
        "BatchMode=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-i",
        identity_file.path().as_str(),
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "RequestTTY=no",
        "-o",
        "EscapeChar=none",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=2",
        "-p",
        "2222",
        "-l",
        "yougori",
        "--",
        "203.0.113.7",
        "'/opt/yougori/bin/yougori-remote' '--launch-vm' '--' 'vm one; $(id)'",
    ]);
    assert_eq!(rendered.argv(), expected.as_slice());
    assert_eq!(rendered.arguments(), &expected[1..]);
    assert_eq!(
        rendered.argv().last().unwrap(),
        invocation.command().as_str()
    );
    assert!(rendered.stdin().is_none());
    assert_eq!(rendered.action(), ManagementAction::LaunchVm);
    assert_eq!(rendered.context(), world.shell());
    assert_eq!(rendered.enrolled(), world.enrollment.fingerprint);
    assert_eq!(rendered.target(), world.key.target());
    // The rendered file still holds exactly the enrolled key.
    assert_eq!(known_hosts.read_back(&world.known), Ok(world.key.clone()));
}

#[test]
fn rsa_ipv6_names_and_port_22_render_as_openssh_expects() {
    let scratch = Scratch::new();
    let world = World::new(
        "[2001:db8::7]",
        HostKeyAlgorithm::RsaSha2_512,
        rsa_blob(3_072, 5),
    );
    let (known_hosts, identity_file) = files(&world, &scratch);
    let invocation = world.launch();
    let rendered = render_invocation(
        &world.identity,
        &world.known,
        &known_hosts,
        &identity_file,
        SshLimits::STANDARD,
        &invocation,
    )
    .unwrap();
    let argv = rendered.argv();
    assert!(argv.contains(&"HostKeyAlgorithms=rsa-sha2-512".to_owned()));
    let tail = &argv[argv.len() - 7..];
    assert_eq!(
        &tail[..6],
        strings(&["-p", "22", "-l", "yougori", "--", "2001:db8::7"]).as_slice()
    );
    assert!(std::fs::read_to_string(known_hosts.path().as_path())
        .unwrap()
        .starts_with("2001:db8::7 ssh-rsa AAAA"));

    let scratch = Scratch::new();
    let world = World::new(
        "Mgmt.Example.net",
        HostKeyAlgorithm::Ed25519,
        ed25519_blob(4),
    );
    let (known_hosts, identity_file) = files(&world, &scratch);
    let invocation = world.launch();
    let rendered = render_invocation(
        &world.identity,
        &world.known,
        &known_hosts,
        &identity_file,
        SshLimits::STANDARD,
        &invocation,
    )
    .unwrap();
    let argv = rendered.argv();
    assert_eq!(argv[argv.len() - 2], "mgmt.example.net");
    assert_eq!(argv[argv.len() - 3], "--");
}

#[test]
fn the_jupyter_password_travels_on_stdin_and_never_in_argv() {
    let world = World::standard();
    let scratch = Scratch::new();
    let (known_hosts, identity_file) = files(&world, &scratch);
    let pod = ExecutionContext::ProviderContainer { host: host_id(1) };
    let invocation = replace_jupyter_password(
        &world.identity,
        &world.known,
        pod,
        &helper(),
        RemoteSecret::new(PASSWORD.to_vec()),
    )
    .unwrap();
    let rendered = render_invocation(
        &world.identity,
        &world.known,
        &known_hosts,
        &identity_file,
        SshLimits::STANDARD,
        &invocation,
    )
    .unwrap();
    for word in rendered.argv() {
        assert!(find_encoded(word.as_bytes(), PASSWORD).is_none(), "{word}");
    }
    let mut line = PASSWORD.to_vec();
    line.push(b'\n');
    assert_eq!(
        rendered.stdin().unwrap().expose_to_transport(),
        line.as_slice()
    );
    let debug = format!("{rendered:?}");
    assert!(!debug.contains("correct-horse"), "{debug}");
    assert!(debug.contains("redacted"));

    let mut port = FakeSshPort::new(rendered.argv().to_vec(), exited(0, ""));
    let run = rendered.run(&mut port);
    assert_eq!(run.outcome, SshOutcome::RemoteExit { code: 0 });
    assert_eq!(port.stdin_seen, vec![Some(line)]);
}

#[test]
fn a_stdin_payload_that_would_appear_in_argv_is_refused() {
    let world = World::standard();
    let scratch = Scratch::new();
    let leaky = KnownHostsFile::write(
        world.key.clone(),
        scratch.path("correct-horse-battery-staple-42"),
    )
    .unwrap();
    let identity_file = IdentityFile::new(super::fakes::mgmt_key(), scratch.path("id"));
    let invocation = replace_jupyter_password(
        &world.identity,
        &world.known,
        ExecutionContext::ProviderContainer { host: host_id(1) },
        &helper(),
        RemoteSecret::new(PASSWORD.to_vec()),
    )
    .unwrap();
    assert_eq!(
        render_invocation(
            &world.identity,
            &world.known,
            &leaky,
            &identity_file,
            SshLimits::STANDARD,
            &invocation,
        )
        .map(|_| ()),
        Err(SshRenderRefusal::SecretInArgv)
    );
}

#[test]
fn injection_shaped_hosts_accounts_ports_and_paths_are_refused_at_the_type_boundary() {
    // Accounts: V12's POSIX account name.
    for account in [
        "",
        "a b",
        "-oProxyCommand=sh",
        "-l",
        "a=b",
        "a\nb",
        "%h",
        "%%",
        "root@host",
        "a;b",
        "Root",
    ] {
        assert_eq!(
            RemoteAccountName::new(account),
            Err(ManagementRefusal::InvalidAccount),
            "{account:?}"
        );
    }
    // Hosts and ports: V02's canonical authority.
    let port_22 = DestinationPort::new(22).unwrap();
    for host in [
        "",
        "a b.example",
        "-oproxycommand=sh.example",
        "-host.example",
        "a=b.example",
        "host\n.example",
        "host.example\n",
        "%h.example",
        "host%2eexample",
        "user@host.example",
        "ssh://host.example",
        "host.example:0",
        "host.example:022",
        "host.example:-22",
        "host.example:22 -oProxyCommand=x",
        "localhost",
        "[fe80::1%25eth0]",
        "[2001:DB8::7]",
        "2001:db8::7",
        "0x7f.0.0.1",
    ] {
        assert!(Authority::parse(host, port_22).is_err(), "{host:?}");
    }
    assert!(DestinationPort::new(0).is_err());
    // Paths: nothing OpenSSH could split, expand or read as an option.
    for (path, refusal) in [
        ("relative/known_hosts", SshPathRefusal::NotAbsolute),
        ("~/.ssh/known_hosts", SshPathRefusal::NotAbsolute),
        ("-oProxyCommand=x", SshPathRefusal::NotAbsolute),
        ("C:\\Users\\kh", SshPathRefusal::NotAbsolute),
        ("C:kh", SshPathRefusal::NotAbsolute),
        ("", SshPathRefusal::NotAbsolute),
        (
            "/tmp/known hosts",
            SshPathRefusal::InvalidCharacter { character: ' ' },
        ),
        (
            "/tmp/kh\nProxyCommand=x",
            SshPathRefusal::InvalidCharacter { character: '\n' },
        ),
        (
            "/tmp/kh=x",
            SshPathRefusal::InvalidCharacter { character: '=' },
        ),
        (
            "/tmp/%h",
            SshPathRefusal::InvalidCharacter { character: '%' },
        ),
        (
            "/home/${USER}/kh",
            SshPathRefusal::InvalidCharacter { character: '$' },
        ),
        (
            "/tmp/\"kh\"",
            SshPathRefusal::InvalidCharacter { character: '"' },
        ),
        (
            "/tmp/kh#x",
            SshPathRefusal::InvalidCharacter { character: '#' },
        ),
        (
            "/tmp/a,b",
            SshPathRefusal::InvalidCharacter { character: ',' },
        ),
        (
            "/tmp/a\\b",
            SshPathRefusal::InvalidCharacter { character: '\\' },
        ),
        (
            "/tmp/ü",
            SshPathRefusal::InvalidCharacter { character: 'ü' },
        ),
        ("/", SshPathRefusal::InvalidComponent),
        ("/tmp/../etc/kh", SshPathRefusal::InvalidComponent),
        ("/tmp/./kh", SshPathRefusal::InvalidComponent),
        ("/tmp//kh", SshPathRefusal::InvalidComponent),
        ("/tmp/kh/", SshPathRefusal::InvalidComponent),
        ("//server/share/kh", SshPathRefusal::InvalidComponent),
    ] {
        assert_eq!(SshFilePath::new(path), Err(refusal), "{path:?}");
    }
    assert!(matches!(
        SshFilePath::new(format!("/{}", "a".repeat(MAX_SSH_PATH_BYTES))),
        Err(SshPathRefusal::TooLong { .. })
    ));
    #[cfg(windows)]
    let good = [
        "D:/run/yougori/known_hosts",
        "C:/Users/me/kh",
        "C:/a/b-c_d.e+f",
    ];
    #[cfg(not(windows))]
    let good = ["/run/yougori/known_hosts", "/a/b-c_d.e+f"];
    for good in good {
        assert_eq!(SshFilePath::new(good).unwrap().as_str(), good);
    }
}

#[test]
fn limits_are_typed_bounded_and_rendered() {
    let s = Duration::from_secs;
    let out_of_range = |limit, min, max| Err(SshLimitsRefusal::OutOfRange { limit, min, max });
    assert_eq!(
        SshLimits::new(0, 10, 2, s(120), 1, 1),
        out_of_range(SshLimit::ConnectTimeout, 1, 3_600)
    );
    assert_eq!(
        SshLimits::new(3_601, 10, 2, s(7_200), 1, 1),
        out_of_range(SshLimit::ConnectTimeout, 1, 3_600)
    );
    assert_eq!(
        SshLimits::new(10, 0, 2, s(120), 1, 1),
        out_of_range(SshLimit::ServerAliveInterval, 1, 3_600)
    );
    assert_eq!(
        SshLimits::new(10, 10, 0, s(120), 1, 1),
        out_of_range(SshLimit::ServerAliveCountMax, 1, 100)
    );
    assert_eq!(
        SshLimits::new(10, 10, 101, s(120), 1, 1),
        out_of_range(SshLimit::ServerAliveCountMax, 1, 100)
    );
    assert_eq!(
        SshLimits::new(10, 10, 2, Duration::from_millis(500), 1, 1),
        out_of_range(SshLimit::Deadline, 1, 86_400)
    );
    assert_eq!(
        SshLimits::new(10, 10, 2, s(86_401), 1, 1),
        out_of_range(SshLimit::Deadline, 1, 86_400)
    );
    assert_eq!(
        SshLimits::new(10, 10, 2, s(5), 1, 1),
        Err(SshLimitsRefusal::DeadlineBeforeConnectTimeout)
    );
    assert_eq!(
        SshLimits::new(10, 10, 2, s(120), 0, 1),
        out_of_range(SshLimit::MaxStdout, 1, 64 * 1024 * 1024)
    );
    assert_eq!(
        SshLimits::new(10, 10, 2, s(120), 1, 64 * 1024 * 1024 + 1),
        out_of_range(SshLimit::MaxStderr, 1, 64 * 1024 * 1024)
    );
    assert_eq!(
        SshLimits::new(10, 10, 2, s(120), 256 * 1024, 256 * 1024),
        Ok(SshLimits::STANDARD)
    );

    let limits = SshLimits::new(5, 15, 4, s(30), 1_024, 2_048).unwrap();
    let world = World::standard();
    let scratch = Scratch::new();
    let (known_hosts, identity_file) = files(&world, &scratch);
    let invocation = world.launch();
    let rendered = render_invocation(
        &world.identity,
        &world.known,
        &known_hosts,
        &identity_file,
        limits,
        &invocation,
    )
    .unwrap();
    for option in [
        "ConnectTimeout=5",
        "ServerAliveInterval=15",
        "ServerAliveCountMax=4",
    ] {
        assert!(rendered.argv().contains(&option.to_owned()), "{option}");
    }
    assert_eq!(rendered.limits(), limits);
}

#[test]
fn stale_identities_foreign_files_and_wrong_keys_are_refused() {
    let scratch = Scratch::new();
    let mut world = World::standard();
    let (known_hosts, identity_file) = files(&world, &scratch);
    let render = |world: &World,
                  identity: &crate::sandbox_contract::remote::ManagementIdentity,
                  known_hosts: &KnownHostsFile,
                  identity_file: &IdentityFile,
                  invocation: &RemoteInvocation| {
        render_invocation(
            identity,
            &world.known,
            known_hosts,
            identity_file,
            SshLimits::STANDARD,
            invocation,
        )
        .map(|_| ())
    };
    let launch = world.launch();

    // An identity that does not permit the action.
    let logs_only = identity_for(&world.enrollment, &[ManagementAction::CollectLogs]);
    assert_eq!(
        render(&world, &logs_only, &known_hosts, &identity_file, &launch),
        Err(SshRenderRefusal::Management {
            refusal: ManagementRefusal::ActionNotPermitted {
                action: ManagementAction::LaunchVm
            }
        })
    );

    // An identity file for another client key.
    let foreign_key = IdentityFile::new(other_key(), identity_file.path().clone());
    assert_eq!(
        render(&world, &world.identity, &known_hosts, &foreign_key, &launch),
        Err(SshRenderRefusal::IdentityFileForAnotherKey)
    );

    // A second host, its own identity, invocation and file.
    let second_key = HostKey::new(HostKeyAlgorithm::Ed25519, ed25519_blob(2)).unwrap();
    let second = world
        .known
        .enroll(
            host_id(2),
            &second_key,
            EnrollmentEvidence::ProviderApi {
                reported: second_key.fingerprint(),
            },
            EnrollmentPolicy::default(),
            MonotonicTime::ZERO,
        )
        .unwrap();
    let second_identity = identity_for(&second, &ManagementAction::ALL);
    let second_launch = RemoteInvocation::new(
        &second_identity,
        &world.known,
        ManagementAction::LaunchVm,
        ExecutionContext::RemoteHostShell { host: host_id(2) },
        &launch_command(),
    )
    .unwrap();
    assert_eq!(
        render(
            &world,
            &world.identity,
            &known_hosts,
            &identity_file,
            &second_launch
        ),
        Err(SshRenderRefusal::Management {
            refusal: ManagementRefusal::WrongHost {
                identity: host_id(1),
                context: host_id(2),
            }
        })
    );
    let second_file = KnownHostsFile::write(
        EnrolledHostKey::new(
            &world.known,
            SshTarget::new(host_id(2), authority("203.0.113.8")),
            HostKeyAlgorithm::Ed25519,
            ed25519_blob(2),
        )
        .unwrap(),
        scratch.path("second_known_hosts"),
    )
    .unwrap();
    assert_eq!(
        render(
            &world,
            &world.identity,
            &second_file,
            &identity_file,
            &launch
        ),
        Err(SshRenderRefusal::KnownHostsForAnotherHost {
            identity: host_id(1),
            file: host_id(2),
        })
    );

    // The host is re-enrolled with the same key: the old identity is stale, and a fresh
    // identity still refuses the file rendered for the old enrollment.
    world.known.retire(&host_id(1));
    assert!(matches!(
        render(
            &world,
            &world.identity,
            &known_hosts,
            &identity_file,
            &launch
        ),
        Err(SshRenderRefusal::Management {
            refusal: ManagementRefusal::StaleEnrollment { .. }
        })
    ));
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
            MonotonicTime::from_nanos(9),
        )
        .unwrap();
    let fresh = identity_for(&again, &ManagementAction::ALL);
    let fresh_launch = RemoteInvocation::new(
        &fresh,
        &world.known,
        ManagementAction::LaunchVm,
        world.shell(),
        &launch_command(),
    )
    .unwrap();
    assert_eq!(
        render(&world, &fresh, &known_hosts, &identity_file, &fresh_launch),
        Err(SshRenderRefusal::KnownHosts {
            refusal: KnownHostsRefusal::StaleEnrollment {
                host: host_id(1),
                rendered: world.enrollment.generation,
                current: again.generation,
            }
        })
    );
}

#[test]
fn the_port_receives_exactly_the_rendered_argv_and_no_stdin_without_a_payload() {
    let world = World::standard();
    let scratch = Scratch::new();
    let (known_hosts, identity_file) = files(&world, &scratch);
    let invocation = world.launch();
    let rendered = render_invocation(
        &world.identity,
        &world.known,
        &known_hosts,
        &identity_file,
        SshLimits::STANDARD,
        &invocation,
    )
    .unwrap();
    let mut port = FakeSshPort::new(rendered.argv().to_vec(), exited(0, ""));
    let run = rendered.run(&mut port);
    assert!(run.outcome.succeeded());
    assert_eq!(run.output, exited(0, ""));
    assert_eq!(port.stdin_seen, vec![None]);
}
