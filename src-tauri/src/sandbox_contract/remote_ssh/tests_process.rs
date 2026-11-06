//! Tests for the process port, with this test executable as the OpenSSH client (see
//! `fake_client`): what it is started with and from where, its stdin, its end, the
//! deadline and output bounds, and the classification of what it reports. Nothing here
//! runs `ssh` or opens a socket.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use super::fake_client::{
    Flooded, Record, Script, HOLDER_DIRECTORY, RECORD_FILE, SCRIPT_FILE, SURVIVOR_FILE,
};
use super::fakes::{files, helper, host_id, Scratch, World, PUBLISHED_ED25519_SHA256};
use super::invocation::{render_invocation, IdentityFile, SshInvocation, SshLimits};
use super::known_hosts::KnownHostsFile;
use super::outcome::{
    classify, ConnectionFailure, HostKeyEvidence, OutputStream, PortFailure, SshOutcome, SshOutput,
    SshPort, SshTermination, TimeoutPhase,
};
use super::process::{
    ProcessSshPort, SshClientRefusal, CLIENT_ENVIRONMENT, OUTPUT_DRAIN_WAIT, REAP_WAIT,
};
use crate::sandbox_contract::provider::find_encoded;
use crate::sandbox_contract::remote::{
    replace_jupyter_password, ExecutionContext, RemoteInvocation, RemoteSecret, UncertainCause,
};

const PASSWORD: &[u8] = b"correct-horse-battery-staple-42";

/// How long a sleeping or flooding fake runs before it leaves its survivor mark.
const SURVIVOR_SECONDS: u64 = 3;

/// OpenSSH's report of a changed host key for the standard world's target, then its exit
/// with 255.
const HOST_KEY_CHANGED: &str = "\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n\
Someone could be eavesdropping on you right now (man-in-the-middle attack)!\r\n\
It is also possible that a host key has just been changed.\r\n\
The fingerprint for the ED25519 key sent by the remote host is\r\n\
SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.\r\n\
Please contact your system administrator.\r\n\
Add correct host key in /run/kh to get rid of this message.\r\n\
Offending ED25519 key in /run/kh:1\r\n\
ED25519 host key for [203.0.113.7]:2222 has changed and you have requested strict checking.\r\n\
Host key verification failed.\r\n";

/// This test executable, the fake client.
fn client() -> PathBuf {
    std::env::current_exe().unwrap()
}

/// Limits with room for a whole test executable to start, even on a loaded machine.
fn patient() -> SshLimits {
    SshLimits::new(10, 10, 2, Duration::from_secs(60), 256 * 1024, 256 * 1024).unwrap()
}

/// `path` in the verbatim form `\\?\C:\...`, which takes backslashes only.
fn verbatim(path: &Path) -> PathBuf {
    PathBuf::from(format!(
        "\\\\?\\{}",
        path.to_str().unwrap().replace('/', "\\")
    ))
}

fn temporary_directory(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new().prefix(prefix).tempdir().unwrap()
}

fn exit(stdout: &str, stderr: &str, code: i32) -> Script {
    Script::Exit {
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
        code,
    }
}

/// The standard world with its files, and a working directory for the client.
struct Fixture {
    world: World,
    _scratch: Scratch,
    known_hosts: KnownHostsFile,
    identity_file: IdentityFile,
    work: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let world = World::standard();
        let scratch = Scratch::new();
        let (known_hosts, identity_file) = files(&world, &scratch);
        Self {
            world,
            _scratch: scratch,
            known_hosts,
            identity_file,
            work: temporary_directory("remote-ssh-client-"),
        }
    }

    fn work(&self) -> &Path {
        self.work.path()
    }

    fn render<'a>(&self, invocation: &'a RemoteInvocation, limits: SshLimits) -> SshInvocation<'a> {
        render_invocation(
            &self.world.identity,
            &self.world.known,
            &self.known_hosts,
            &self.identity_file,
            limits,
            invocation,
        )
        .unwrap()
    }

    fn jupyter(&self) -> RemoteInvocation {
        replace_jupyter_password(
            &self.world.identity,
            &self.world.known,
            ExecutionContext::ProviderContainer { host: host_id(1) },
            &helper(),
            RemoteSecret::new(PASSWORD.to_vec()),
        )
        .unwrap()
    }

    fn port(&self) -> ProcessSshPort {
        ProcessSshPort::new(client(), self.work()).unwrap()
    }

    fn script(&self, script: &Script) {
        std::fs::write(
            self.work().join(SCRIPT_FILE),
            serde_json::to_vec(script).unwrap(),
        )
        .unwrap();
    }

    fn record(&self) -> Record {
        serde_json::from_slice(&std::fs::read(self.work().join(RECORD_FILE)).unwrap()).unwrap()
    }

    fn has_record(&self) -> bool {
        self.work().join(RECORD_FILE).exists()
    }

    fn survived(&self) -> bool {
        self.work().join(SURVIVOR_FILE).exists()
    }
}

/// Waits until a fake started at `started` would have left its survivor mark, with room.
fn wait_past_survival(started: Instant) {
    let until = started + Duration::from_secs(SURVIVOR_SECONDS + 3);
    thread::sleep(until.saturating_duration_since(Instant::now()));
}

#[test]
fn the_client_is_the_configured_program_with_exactly_the_rendered_arguments() {
    let fixture = Fixture::new();
    let invocation = fixture.world.launch();
    let rendered = fixture.render(&invocation, patient());
    let mut port = fixture.port();
    assert_eq!(port.program(), client().as_path());
    assert_eq!(port.working_directory(), fixture.work());

    fixture.script(&exit("launched vm-7\n", "remote note\r\n", 0));
    let output = port.run(&rendered);
    assert_eq!(
        output,
        SshOutput {
            termination: SshTermination::Exited { code: 0 },
            stdout: b"launched vm-7\n".to_vec(),
            stderr: b"remote note\r\n".to_vec(),
        }
    );
    assert_eq!(port.last_refusal(), None);
    let record = fixture.record();
    // The rendered program name is replaced by the configured path; the rest is exact.
    assert_eq!(rendered.argv()[0], "ssh");
    assert_eq!(PathBuf::from(&record.program), client());
    assert_eq!(record.arguments, rendered.arguments());
    assert_eq!(record.arguments[..2], ["-F", "none"]);
    assert_eq!(
        record.arguments.last().unwrap(),
        "'/opt/yougori/bin/yougori-remote' '--launch-vm' '--' 'vm one; $(id)'"
    );

    // Exit statuses are reported as the system gives them, including one OpenSSH never
    // uses (a crashed client on Windows), which classification does not take as success.
    for code in [3, 255, -1_073_741_819] {
        fixture.script(&exit("", "", code));
        assert_eq!(
            port.run(&rendered).termination,
            SshTermination::Exited { code }
        );
    }
    fixture.script(&exit("", "", -1_073_741_819));
    assert_eq!(
        rendered.run(&mut port).outcome,
        SshOutcome::Uncertain {
            cause: UncertainCause::AmbiguousResponse
        }
    );
}

#[test]
fn the_client_environment_holds_only_what_the_platform_needs() {
    let fixture = Fixture::new();
    let invocation = fixture.world.launch();
    let rendered = fixture.render(&invocation, patient());
    fixture.script(&exit("", "", 0));
    assert_eq!(
        fixture.port().run(&rendered).termination,
        SshTermination::Exited { code: 0 }
    );
    let record = fixture.record();
    let expected: BTreeMap<String, String> = CLIENT_ENVIRONMENT
        .iter()
        .filter_map(|name| Some(((*name).to_owned(), std::env::var(name).ok()?)))
        .collect();
    assert_eq!(record.environment, expected);
    assert_eq!(CLIENT_ENVIRONMENT, ["SystemRoot", "ProgramData"]);
    assert!(record.environment.contains_key("SystemRoot"));

    // The engine's own environment is larger; none of the rest reached the client.
    let engine: Vec<String> = std::env::vars_os()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    assert!(engine.iter().any(|name| name.eq_ignore_ascii_case("PATH")));
    assert!(engine.len() > record.environment.len());
    for name in [
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "SSH_AUTH_SOCK",
        "SSH_ASKPASS",
        "DISPLAY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ] {
        assert!(
            !record
                .environment
                .keys()
                .any(|key| key.eq_ignore_ascii_case(name)),
            "{name}"
        );
    }
}

#[test]
fn the_client_runs_in_the_working_directory_and_a_none_entry_refuses_it() {
    let fixture = Fixture::new();
    let invocation = fixture.world.launch();
    let rendered = fixture.render(&invocation, patient());
    // Other names are fine.
    std::fs::write(fixture.work().join("none.txt"), b"").unwrap();
    std::fs::create_dir(fixture.work().join("nonesuch")).unwrap();
    fixture.script(&exit("", "", 0));
    let mut port = fixture.port();
    assert_eq!(
        port.run(&rendered).termination,
        SshTermination::Exited { code: 0 }
    );
    assert_eq!(
        std::fs::canonicalize(fixture.record().working_directory).unwrap(),
        std::fs::canonicalize(fixture.work()).unwrap()
    );

    // Refused when the port is made.
    let base = temporary_directory("remote-ssh-dirs-");
    let refused = |directory: &Path| ProcessSshPort::new(client(), directory).map(|_| ());
    for (index, (name, as_directory)) in [("none", false), ("NONE", false), ("None", true)]
        .into_iter()
        .enumerate()
    {
        let directory = base.path().join(format!("case-{index}"));
        std::fs::create_dir(&directory).unwrap();
        if as_directory {
            std::fs::create_dir(directory.join(name)).unwrap();
        } else {
            std::fs::write(directory.join(name), b"").unwrap();
        }
        assert_eq!(
            refused(&directory),
            Err(SshClientRefusal::NoneEntryInWorkingDirectory),
            "{name}"
        );
    }
    assert_eq!(
        refused(&base.path().join("missing")),
        Err(SshClientRefusal::WorkingDirectoryMissing)
    );
    let file = base.path().join("a-file");
    std::fs::write(&file, b"").unwrap();
    assert_eq!(
        refused(&file),
        Err(SshClientRefusal::WorkingDirectoryNotADirectory)
    );
    assert_eq!(
        refused(Path::new("work")),
        Err(SshClientRefusal::WorkingDirectoryNotAbsolute)
    );

    // Checked again before every start: an entry named `none` that appeared later stops
    // the run before the client starts.
    std::fs::remove_file(fixture.work().join(RECORD_FILE)).unwrap();
    std::fs::write(fixture.work().join("none"), b"").unwrap();
    let output = port.run(&rendered);
    assert_eq!(
        output,
        SshOutput {
            termination: SshTermination::NotStarted,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    );
    assert_eq!(
        port.last_refusal(),
        Some(&SshClientRefusal::NoneEntryInWorkingDirectory)
    );
    assert!(!fixture.has_record());
    assert_eq!(
        classify(&rendered, &output),
        SshOutcome::ConnectionFailed {
            failure: ConnectionFailure::ClientNotStarted
        }
    );
}

#[test]
fn the_stdin_payload_is_written_once_then_closed_and_no_payload_is_an_empty_stdin() {
    let fixture = Fixture::new();
    let jupyter = fixture.jupyter();
    let rendered = fixture.render(&jupyter, patient());
    fixture.script(&exit("", "", 0));
    let mut port = fixture.port();
    // The fake reads its stdin to the end before it records and exits, so an exit at
    // all shows stdin was closed after the payload.
    let run = rendered.run(&mut port);
    assert_eq!(run.output.termination, SshTermination::Exited { code: 0 });
    assert!(run.outcome.succeeded());
    let record = fixture.record();
    let mut line = PASSWORD.to_vec();
    line.push(b'\n');
    assert_eq!(record.stdin, line);
    for word in record
        .arguments
        .iter()
        .chain(record.environment.values())
        .chain(std::iter::once(&record.program))
    {
        assert!(find_encoded(word.as_bytes(), PASSWORD).is_none(), "{word}");
    }

    let launch = fixture.world.launch();
    let rendered = fixture.render(&launch, patient());
    assert_eq!(
        port.run(&rendered).termination,
        SshTermination::Exited { code: 0 }
    );
    assert_eq!(fixture.record().stdin, Vec::<u8>::new());
}

#[test]
fn the_deadline_kills_the_client_and_reports_deadline_reached() {
    let fixture = Fixture::new();
    let invocation = fixture.world.launch();
    let limits = SshLimits::new(1, 1, 1, Duration::from_secs(1), 1_024, 1_024).unwrap();
    let rendered = fixture.render(&invocation, limits);
    fixture.script(&Script::Sleep {
        seconds: SURVIVOR_SECONDS,
    });
    let started = Instant::now();
    let output = fixture.port().run(&rendered);
    let elapsed = started.elapsed();
    assert_eq!(output.termination, SshTermination::DeadlineReached);
    assert!(
        elapsed >= limits.deadline() && elapsed < limits.deadline() + REAP_WAIT,
        "{elapsed:?}"
    );
    let outcome = classify(&rendered, &output);
    assert_eq!(
        outcome,
        SshOutcome::TimedOut {
            phase: TimeoutPhase::Deadline
        }
    );
    assert!(!outcome.succeeded() && outcome.command_may_have_run());
    // The client was killed, not left sleeping: it never left its mark.
    wait_past_survival(started);
    assert!(!fixture.survived());
}

/// Floods one stream past a small bound and checks the client was killed at it.
fn flood(flooded: Flooded) {
    let fixture = Fixture::new();
    let invocation = fixture.world.launch();
    let limits = SshLimits::new(10, 10, 2, Duration::from_secs(60), 4_096, 2_048).unwrap();
    let rendered = fixture.render(&invocation, limits);
    fixture.script(&Script::Flood {
        stream: flooded,
        seconds: SURVIVOR_SECONDS,
    });
    let started = Instant::now();
    let output = fixture.port().run(&rendered);
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(output.termination, SshTermination::NoExitStatus);
    let (stream, flooded_bytes, quiet_bytes, max_bytes) = match flooded {
        Flooded::Stdout => (
            OutputStream::Stdout,
            &output.stdout,
            &output.stderr,
            limits.max_stdout_bytes(),
        ),
        Flooded::Stderr => (
            OutputStream::Stderr,
            &output.stderr,
            &output.stdout,
            limits.max_stderr_bytes(),
        ),
    };
    // Read to one byte over the bound and no further.
    assert_eq!(
        u64::try_from(flooded_bytes.len()).unwrap(),
        max_bytes + 1,
        "{flooded:?}"
    );
    assert!(flooded_bytes.iter().all(|byte| *byte == b'x'));
    assert!(quiet_bytes.is_empty());
    let outcome = classify(&rendered, &output);
    assert_eq!(outcome, SshOutcome::OutputOverBound { stream, max_bytes });
    assert!(!outcome.succeeded());
    wait_past_survival(started);
    assert!(!fixture.survived(), "{flooded:?}");
}

#[test]
fn a_stdout_flood_kills_the_client_and_reports_the_bound() {
    flood(Flooded::Stdout);
}

#[test]
fn a_stderr_flood_kills_the_client_and_reports_the_bound() {
    flood(Flooded::Stderr);
}

#[test]
fn a_relative_or_bare_client_program_is_refused() {
    let work = temporary_directory("remote-ssh-program-");
    for program in [
        "ssh",
        "ssh.exe",
        "",
        "OpenSSH/ssh.exe",
        "./ssh.exe",
        "..\\OpenSSH\\ssh.exe",
        "\\Windows\\System32\\OpenSSH\\ssh.exe",
        "C:ssh.exe",
    ] {
        assert_eq!(
            ProcessSshPort::new(program, work.path()).map(|_| ()),
            Err(SshClientRefusal::ProgramNotAbsolute),
            "{program:?}"
        );
    }
    // On Windows only an `.exe` is started as it is named: anything else would be tried
    // again with `.exe` appended, and a batch file runs through the command shell.
    for program in [
        "C:\\Windows\\System32\\OpenSSH\\ssh",
        "C:\\tools\\ssh.cmd",
        "C:\\tools\\ssh.BAT",
        "C:\\tools\\ssh.exe.",
        "C:\\tools\\ssh.exe.cmd",
    ] {
        assert_eq!(
            ProcessSshPort::new(program, work.path()).map(|_| ()),
            Err(SshClientRefusal::ProgramNotExe),
            "{program:?}"
        );
    }
    // Never from a share, a device path or a verbatim path without a drive.
    for program in [
        "\\\\server\\share\\ssh.exe",
        "//server/share/ssh.exe",
        "\\\\?\\UNC\\server\\share\\ssh.exe",
        "\\\\.\\C:\\Windows\\System32\\OpenSSH\\ssh.exe",
        "\\\\?\\ssh.exe",
        "\\\\?\\C:ssh.exe",
        "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\ssh.exe",
    ] {
        assert_eq!(
            ProcessSshPort::new(program, work.path()).map(|_| ()),
            Err(SshClientRefusal::ProgramNotOnLocalDrive),
            "{program:?}"
        );
    }
    for program in [
        "C:\\Windows\\System32\\OpenSSH\\SSH.EXE",
        "D:/tools/ssh.exe",
        "\\\\?\\C:\\Windows\\System32\\OpenSSH\\ssh.exe",
    ] {
        assert!(
            ProcessSshPort::new(program, work.path()).is_ok(),
            "{program}"
        );
    }
    assert!(ProcessSshPort::new(client(), work.path()).is_ok());
}

#[test]
fn a_verbatim_local_drive_client_runs_and_a_directory_named_like_one_does_not_start() {
    let fixture = Fixture::new();
    let invocation = fixture.world.launch();
    let rendered = fixture.render(&invocation, patient());
    fixture.script(&exit("verbatim\n", "", 0));
    let verbatim = verbatim(&client());
    let mut port = ProcessSshPort::new(&verbatim, fixture.work()).unwrap();
    let output = port.run(&rendered);
    assert_eq!(output.termination, SshTermination::Exited { code: 0 });
    assert_eq!(output.stdout, b"verbatim\n");
    assert_eq!(fixture.record().arguments, rendered.arguments());

    std::fs::remove_file(fixture.work().join(RECORD_FILE)).unwrap();
    let directory = fixture.work().join("ssh.exe");
    std::fs::create_dir(&directory).unwrap();
    let mut port = ProcessSshPort::new(&directory, fixture.work()).unwrap();
    assert_eq!(port.run(&rendered).termination, SshTermination::NotStarted);
    assert!(matches!(
        port.last_refusal(),
        Some(SshClientRefusal::StartFailed { .. })
    ));
    assert!(!fixture.has_record());
}

#[test]
fn a_working_directory_on_a_share_or_device_is_refused_and_a_verbatim_local_one_runs() {
    // Refused before the file system is asked anything, so no share is contacted.
    for directory in [
        "\\\\server\\share\\work",
        "//server/share/work",
        "\\\\?\\UNC\\server\\share\\work",
        "\\\\.\\C:\\work",
        "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\work",
    ] {
        assert_eq!(
            ProcessSshPort::new(client(), directory).map(|_| ()),
            Err(SshClientRefusal::WorkingDirectoryNotOnLocalDrive),
            "{directory:?}"
        );
    }
    assert_eq!(
        ProcessSshPort::new(client(), "\\work").map(|_| ()),
        Err(SshClientRefusal::WorkingDirectoryNotAbsolute)
    );

    let fixture = Fixture::new();
    let invocation = fixture.world.launch();
    let rendered = fixture.render(&invocation, patient());
    fixture.script(&exit("", "", 0));
    let verbatim = verbatim(fixture.work());
    let mut port = ProcessSshPort::new(client(), &verbatim).unwrap();
    assert_eq!(
        port.run(&rendered).termination,
        SshTermination::Exited { code: 0 }
    );
    assert_eq!(
        std::fs::canonicalize(fixture.record().working_directory).unwrap(),
        std::fs::canonicalize(fixture.work()).unwrap()
    );
}

#[test]
fn a_client_that_ends_while_another_process_holds_its_pipes_reports_its_exit() {
    const HOLDER_SECONDS: u64 = 8;
    let fixture = Fixture::new();
    let invocation = fixture.world.launch();
    let rendered = fixture.render(&invocation, patient());
    fixture.script(&Script::ExitLeavingHolder {
        stdout: "client done\n".to_owned(),
        holder_seconds: HOLDER_SECONDS,
    });
    let started = Instant::now();
    let output = fixture.port().run(&rendered);
    let elapsed = started.elapsed();
    assert_eq!(output.termination, SshTermination::Exited { code: 0 });
    assert_eq!(output.stdout, b"client done\n");
    assert!(output.stderr.is_empty());
    assert!(classify(&rendered, &output).succeeded());
    // The holder kept both pipes open, so the readers never reached their end: the port
    // drained for its bound and reported, long before the holder let go and far before
    // the 60 s deadline.
    assert!(elapsed >= OUTPUT_DRAIN_WAIT, "{elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(HOLDER_SECONDS - 2),
        "{elapsed:?}"
    );

    // The holder was alive all along; let it finish so nothing outlives the test.
    let holder_mark = fixture.work().join(HOLDER_DIRECTORY).join(SURVIVOR_FILE);
    let patience = Instant::now() + Duration::from_secs(HOLDER_SECONDS + 20);
    while !holder_mark.exists() && Instant::now() < patience {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(holder_mark.exists());
}

#[test]
fn a_local_fault_of_the_port_is_an_ambiguous_response_not_a_lost_connection() {
    let fixture = Fixture::new();
    let invocation = fixture.world.launch();
    let rendered = fixture.render(&invocation, patient());
    for failure in [
        PortFailure::PipeMissing,
        PortFailure::ThreadNotStarted,
        PortFailure::ReadFailed,
        PortFailure::WaitFailed,
    ] {
        let output = SshOutput {
            termination: SshTermination::PortFailed { failure },
            stdout: b"partial".to_vec(),
            stderr: vec![b'e'; 1 << 20],
        };
        let outcome = classify(&rendered, &output);
        assert_eq!(
            outcome,
            SshOutcome::Uncertain {
                cause: UncertainCause::AmbiguousResponse
            },
            "{failure:?}"
        );
        assert!(outcome.command_may_have_run() && !outcome.succeeded());
    }
    let json = serde_json::to_value(SshTermination::PortFailed {
        failure: PortFailure::ReadFailed,
    })
    .unwrap();
    assert_eq!(json["termination"], "port_failed");
    assert_eq!(json["failure"], "read_failed");
}

#[test]
fn a_client_program_that_does_not_exist_is_not_started() {
    let fixture = Fixture::new();
    let invocation = fixture.world.launch();
    let rendered = fixture.render(&invocation, patient());
    fixture.script(&exit("", "", 0));
    let missing = fixture.work().join("no-such-ssh.exe");
    let mut port = ProcessSshPort::new(&missing, fixture.work()).unwrap();
    let run = rendered.run(&mut port);
    assert_eq!(
        run.output,
        SshOutput {
            termination: SshTermination::NotStarted,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    );
    assert!(matches!(
        port.last_refusal(),
        Some(SshClientRefusal::StartFailed { .. })
    ));
    assert_eq!(
        run.outcome,
        SshOutcome::ConnectionFailed {
            failure: ConnectionFailure::ClientNotStarted
        }
    );
    assert!(!run.outcome.command_may_have_run());
    assert!(!fixture.has_record());
}

#[test]
fn end_to_end_a_remote_exit_0_succeeds_and_a_changed_host_key_ends_delegation() {
    let fixture = Fixture::new();
    let invocation = fixture.world.launch();
    let rendered = fixture.render(&invocation, patient());
    let mut port = fixture.port();

    fixture.script(&exit("vm-7 running\n", "", 0));
    let run = rendered.run(&mut port);
    assert_eq!(run.outcome, SshOutcome::RemoteExit { code: 0 });
    assert!(run.outcome.succeeded());
    assert_eq!(run.output.stdout, b"vm-7 running\n");

    fixture.script(&exit("", HOST_KEY_CHANGED, 255));
    let run = rendered.run(&mut port);
    assert_eq!(run.output.termination, SshTermination::Exited { code: 255 });
    assert_eq!(run.output.stderr, HOST_KEY_CHANGED.as_bytes());
    assert_eq!(
        run.outcome,
        SshOutcome::HostKeyMismatch {
            host: host_id(1),
            enrolled: fixture.world.enrollment.fingerprint,
            evidence: HostKeyEvidence::Changed {
                reported: Some(PUBLISHED_ED25519_SHA256.to_owned())
            },
        }
    );
    assert!(run.outcome.ends_delegation());
    assert!(!run.outcome.command_may_have_run());
    assert!(!run.outcome.succeeded());
}
