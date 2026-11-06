//! Tests for the classification of what the OpenSSH client reported, from fake outputs.

use super::fakes::{exited, files, host_id, FakeSshPort, Scratch, World, PUBLISHED_ED25519_SHA256};
use super::invocation::{render_invocation, IdentityFile, SshInvocation, SshLimits};
use super::known_hosts::KnownHostsFile;
use super::outcome::{
    classify, ConnectionFailure, HostKeyEvidence, OutputStream, SshOutcome, SshOutput,
    SshTermination, TimeoutPhase,
};
use crate::sandbox_contract::remote::{HostKeyAlgorithm, RemoteInvocation, UncertainCause};

struct Fixture {
    world: World,
    _scratch: Scratch,
    known_hosts: KnownHostsFile,
    identity_file: IdentityFile,
    invocation: RemoteInvocation,
}

impl Fixture {
    fn new(address: &str) -> Self {
        let world = World::new(
            address,
            HostKeyAlgorithm::Ed25519,
            super::fakes::ed25519_blob(1),
        );
        let scratch = Scratch::new();
        let (known_hosts, identity_file) = files(&world, &scratch);
        let invocation = world.launch();
        Self {
            world,
            _scratch: scratch,
            known_hosts,
            identity_file,
            invocation,
        }
    }

    fn rendered(&self) -> SshInvocation<'_> {
        render_invocation(
            &self.world.identity,
            &self.world.known,
            &self.known_hosts,
            &self.identity_file,
            SshLimits::STANDARD,
            &self.invocation,
        )
        .unwrap()
    }

    fn classify(&self, output: &SshOutput) -> SshOutcome {
        classify(&self.rendered(), output)
    }

    fn client_error(&self, stderr: &str) -> SshOutcome {
        self.classify(&exited(255, stderr))
    }

    fn mismatch(&self, evidence: HostKeyEvidence) -> SshOutcome {
        SshOutcome::HostKeyMismatch {
            host: host_id(1),
            enrolled: self.world.enrollment.fingerprint,
            evidence,
        }
    }
}

const CHANGED: &str = "\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n\
Someone could be eavesdropping on you right now (man-in-the-middle attack)!\r\n\
It is also possible that a host key has just been changed.\r\n\
The fingerprint for the ED25519 key sent by the remote host is\n\
SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.\r\n\
Please contact your system administrator.\r\n\
Add correct host key in /run/kh to get rid of this message.\r\n\
Offending ED25519 key in /run/kh:1\r\n\
ED25519 host key for [203.0.113.7]:2222 has changed and you have requested strict checking.\r\n\
Host key verification failed.\r\n";

#[test]
fn remote_exit_codes_are_read_from_0_to_254_whatever_stderr_says() {
    let fixture = Fixture::new("203.0.113.7:2222");
    assert_eq!(
        fixture.classify(&exited(0, "")),
        SshOutcome::RemoteExit { code: 0 }
    );
    assert!(fixture.classify(&exited(0, "")).succeeded());
    for code in [1u8, 3, 127, 254] {
        let outcome = fixture.classify(&exited(i32::from(code), "Host key verification failed.\n"));
        assert_eq!(outcome, SshOutcome::RemoteExit { code });
        assert!(!outcome.succeeded());
        assert!(outcome.command_may_have_run());
        assert!(!outcome.ends_delegation());
    }
}

#[test]
fn a_changed_host_key_is_a_mismatch_that_ends_delegation() {
    let fixture = Fixture::new("203.0.113.7:2222");
    let outcome = fixture.client_error(CHANGED);
    assert_eq!(
        outcome,
        fixture.mismatch(HostKeyEvidence::Changed {
            reported: Some(PUBLISHED_ED25519_SHA256.to_owned())
        })
    );
    assert!(outcome.ends_delegation());
    assert!(!outcome.command_may_have_run());
    assert!(!outcome.succeeded());
    let json = serde_json::to_value(&outcome).unwrap();
    assert_eq!(json["outcome"], "host_key_mismatch");
    assert_eq!(json["evidence"]["evidence"], "changed");
    assert_eq!(json["evidence"]["reported"], PUBLISHED_ED25519_SHA256);

    // LF endings and no fingerprint line read the same, without the fingerprint.
    let plain = CHANGED
        .replace("\r\n", "\n")
        .replace("SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.\n", "");
    assert_eq!(
        fixture.client_error(&plain),
        fixture.mismatch(HostKeyEvidence::Changed { reported: None })
    );
    // A change reported for another host pattern is still a failed verification.
    let elsewhere = CHANGED.replace("[203.0.113.7]:2222 has", "[203.0.113.8]:2222 has");
    assert_eq!(
        fixture.client_error(&elsewhere),
        fixture.mismatch(HostKeyEvidence::Unverified)
    );
    assert_eq!(
        fixture.client_error(
            "No ED25519 host key is known for [203.0.113.7]:2222 and you have requested strict \
             checking.\r\nHost key verification failed.\r\n"
        ),
        fixture.mismatch(HostKeyEvidence::Unverified)
    );
    assert_eq!(
        fixture.client_error(
            "Unable to negotiate with 203.0.113.7 port 2222: no matching host key type found. \
             Their offer: rsa-sha2-512,ecdsa-sha2-nistp256\r\n"
        ),
        fixture.mismatch(HostKeyEvidence::AlgorithmNotOffered)
    );
}

#[test]
fn authentication_refusals_are_recognised_only_for_this_account_and_host() {
    let fixture = Fixture::new("203.0.113.7:2222");
    let refused = |methods: &str, identity_file_unusable| SshOutcome::AuthenticationRefused {
        methods: methods.to_owned(),
        identity_file_unusable,
    };
    assert_eq!(
        fixture.client_error("yougori@203.0.113.7: Permission denied (publickey).\r\n"),
        refused("publickey", false)
    );
    assert_eq!(
        fixture.client_error("Permission denied (publickey,password).\r\n"),
        refused("publickey,password", false)
    );
    let unusable = format!(
        "Load key \"{}\": bad permissions\r\nyougori@203.0.113.7: Permission denied \
         (publickey).\r\n",
        fixture.identity_file.path()
    );
    assert_eq!(fixture.client_error(&unusable), refused("publickey", true));
    let outcome = fixture.client_error(&unusable);
    assert!(!outcome.command_may_have_run() && !outcome.ends_delegation());
    for other in [
        "root@203.0.113.7: Permission denied (publickey).\r\n",
        "yougori@203.0.113.8: Permission denied (publickey).\r\n",
        "yougori@203.0.113.7: Permission denied (publickey).\r\nremote output\r\n",
        "Permission denied (Public Key).\r\n",
        "Permission denied ().\r\n",
    ] {
        assert_eq!(
            fixture.client_error(other),
            SshOutcome::Uncertain {
                cause: UncertainCause::AmbiguousResponse
            },
            "{other:?}"
        );
    }
}

#[test]
fn connection_failures_and_timeouts_are_typed_by_their_messages() {
    let fixture = Fixture::new("203.0.113.7:2222");
    let failed = |failure| SshOutcome::ConnectionFailed { failure };
    let connect =
        |reason: &str| format!("ssh: connect to host 203.0.113.7 port 2222: {reason}\r\n");
    for (stderr, outcome) in [
        (
            connect("Connection refused"),
            failed(ConnectionFailure::Refused),
        ),
        (
            connect("No route to host"),
            failed(ConnectionFailure::Unreachable),
        ),
        (
            connect("Network is unreachable"),
            failed(ConnectionFailure::Unreachable),
        ),
        (
            connect("Permission denied"),
            failed(ConnectionFailure::ConnectFailed),
        ),
        (
            connect("Connection timed out"),
            SshOutcome::TimedOut {
                phase: TimeoutPhase::Connect,
            },
        ),
        (
            connect("Operation timed out"),
            SshOutcome::TimedOut {
                phase: TimeoutPhase::Connect,
            },
        ),
        (
            "Connection timed out during banner exchange\r\nConnection to 203.0.113.7 port 2222 \
             timed out\r\n"
                .to_owned(),
            SshOutcome::TimedOut {
                phase: TimeoutPhase::Connect,
            },
        ),
        (
            "Connection timed out during banner exchange\r\n".to_owned(),
            SshOutcome::TimedOut {
                phase: TimeoutPhase::Connect,
            },
        ),
        (
            "kex_exchange_identification: Connection closed by remote host\r\nConnection closed \
             by 203.0.113.7 port 2222\r\n"
                .to_owned(),
            failed(ConnectionFailure::Handshake),
        ),
        (
            "kex_exchange_identification: read: Connection reset by peer\r\nConnection reset by \
             203.0.113.7 port 2222\r\n"
                .to_owned(),
            failed(ConnectionFailure::Handshake),
        ),
        (
            "Unable to negotiate with 203.0.113.7 port 2222: no matching key exchange method \
             found. Their offer: diffie-hellman-group1-sha1\r\n"
                .to_owned(),
            failed(ConnectionFailure::Negotiation),
        ),
        (
            "Timeout, server 203.0.113.7 not responding.\r\n".to_owned(),
            SshOutcome::TimedOut {
                phase: TimeoutPhase::ServerUnresponsive,
            },
        ),
        (
            "Connection to 203.0.113.7 closed by remote host.\r\n".to_owned(),
            SshOutcome::Uncertain {
                cause: UncertainCause::ConnectionLost,
            },
        ),
    ] {
        assert_eq!(fixture.client_error(&stderr), outcome, "{stderr:?}");
    }
    // Pre-session failures did not run the command; a keepalive timeout may have.
    assert!(!fixture
        .client_error(&connect("Connection refused"))
        .command_may_have_run());
    assert!(!fixture
        .client_error(&connect("Connection timed out"))
        .command_may_have_run());
    assert!(fixture
        .client_error("Timeout, server 203.0.113.7 not responding.\r\n")
        .command_may_have_run());

    let named = Fixture::new("mgmt.example.net:2222");
    for stderr in [
        "ssh: Could not resolve hostname mgmt.example.net: Name or service not known\r\n",
        "ssh.exe: Could not resolve hostname mgmt.example.net: No such host is known. \r\n",
    ] {
        assert_eq!(
            named.client_error(stderr),
            failed(ConnectionFailure::NameNotResolved),
            "{stderr:?}"
        );
    }
    assert_eq!(
        named.client_error("ssh: connect to host mgmt.example.net port 2222: Connection refused\n"),
        failed(ConnectionFailure::Refused)
    );
}

#[test]
fn exit_255_with_an_unknown_or_foreign_message_is_uncertain_never_success() {
    let fixture = Fixture::new("203.0.113.7:2222");
    let ambiguous = SshOutcome::Uncertain {
        cause: UncertainCause::AmbiguousResponse,
    };
    for stderr in [
        "",
        "\r\n \r\n",
        "ssh: something new happened\r\n",
        "ssh: connect to host 203.0.113.8 port 2222: Connection refused\r\n",
        "ssh: connect to host 203.0.113.7 port 22: Connection refused\r\n",
        "ssh: Could not resolve hostname other.example.net: Name or service not known\r\n",
        "Timeout, server 203.0.113.8 not responding.\r\n",
        "Unable to negotiate with 203.0.113.7 port 22: no matching host key type found. Their \
         offer: ssh-rsa\r\n",
        "Host key verification failed.\r\nbut the remote kept talking\r\n",
        "Connection timed out during banner exchange\r\nsomething else\r\n",
        "\u{fffd}\u{fffd} binary noise",
    ] {
        let outcome = fixture.client_error(stderr);
        assert_eq!(outcome, ambiguous, "{stderr:?}");
        assert!(!outcome.succeeded());
        assert!(outcome.command_may_have_run());
    }
    assert_eq!(
        fixture.classify(&SshOutput {
            termination: SshTermination::Exited { code: 255 },
            stdout: b"done\n".to_vec(),
            stderr: vec![0xff, 0xfe, b'\n'],
        }),
        ambiguous
    );
    // Statuses OpenSSH never reports, such as a crashed client on Windows.
    for code in [256, -1, -1_073_741_819, i32::MAX] {
        assert_eq!(fixture.classify(&exited(code, "")), ambiguous, "{code}");
    }
}

#[test]
fn terminations_without_a_status_and_output_over_a_bound_are_never_success() {
    let fixture = Fixture::new("203.0.113.7:2222");
    let output = |termination| SshOutput {
        termination,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    assert_eq!(
        fixture.classify(&output(SshTermination::NoExitStatus)),
        SshOutcome::Uncertain {
            cause: UncertainCause::ConnectionLost
        }
    );
    assert_eq!(
        fixture.classify(&output(SshTermination::DeadlineReached)),
        SshOutcome::TimedOut {
            phase: TimeoutPhase::Deadline
        }
    );
    assert!(fixture
        .classify(&output(SshTermination::DeadlineReached))
        .command_may_have_run());
    let not_started = fixture.classify(&output(SshTermination::NotStarted));
    assert_eq!(
        not_started,
        SshOutcome::ConnectionFailed {
            failure: ConnectionFailure::ClientNotStarted
        }
    );
    assert!(!not_started.command_may_have_run());

    let bound = SshLimits::STANDARD.max_stdout_bytes();
    let at_bound = SshOutput {
        termination: SshTermination::Exited { code: 0 },
        stdout: vec![b'x'; usize::try_from(bound).unwrap()],
        stderr: Vec::new(),
    };
    assert!(fixture.classify(&at_bound).succeeded());
    let mut over = at_bound.clone();
    over.stdout.push(b'x');
    let outcome = fixture.classify(&over);
    assert_eq!(
        outcome,
        SshOutcome::OutputOverBound {
            stream: OutputStream::Stdout,
            max_bytes: bound,
        }
    );
    assert!(!outcome.succeeded() && outcome.command_may_have_run());
    let noisy = SshOutput {
        termination: SshTermination::Exited { code: 255 },
        stdout: Vec::new(),
        stderr: vec![b'e'; usize::try_from(SshLimits::STANDARD.max_stderr_bytes()).unwrap() + 1],
    };
    assert_eq!(
        fixture.classify(&noisy),
        SshOutcome::OutputOverBound {
            stream: OutputStream::Stderr,
            max_bytes: SshLimits::STANDARD.max_stderr_bytes(),
        }
    );
}

#[test]
fn a_run_through_the_port_classifies_a_host_key_mismatch() {
    let fixture = Fixture::new("203.0.113.7:2222");
    let rendered = fixture.rendered();
    let mut port = FakeSshPort::new(rendered.argv().to_vec(), exited(255, CHANGED));
    let run = rendered.run(&mut port);
    assert!(run.outcome.ends_delegation());
    assert_eq!(run.output.stderr, CHANGED.as_bytes());
    assert_eq!(port.stdin_seen, vec![None]);
}
