//! The process port: the program and home checks, the exact command it builds (argv and
//! environment), and real runs of this test executable standing in for runpodctl: an
//! exit with its status and output, the deadline and an output bound, each kept by
//! killing it. Nothing here runs runpodctl or opens a socket.

use std::ffi::OsStr;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::command::{RunPodCommand, RunpodctlInvocation, RunpodctlLimits};
use super::fakes::KEY;
use super::process::{
    supervise, ProcessRunpodctl, RunpodctlPort, RunpodctlRefusal, FIXED_ENVIRONMENT, HOME_VARIABLE,
    INHERITED_ENVIRONMENT,
};
use super::secret::API_KEY_VARIABLE;
use crate::sandbox_contract::provider::{find_encoded, SecretValue};
use crate::sandbox_contract::remote_ssh::{SshTermination, REAP_WAIT};

/// Selects what [`runpodctl_helper_process`] does when started by these tests.
const HELPER_MODE: &str = "YG_RUNPODCTL_HELPER_MODE";

/// This test executable.
fn this_executable() -> PathBuf {
    std::env::current_exe().unwrap()
}

fn temporary_directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("runpodctl-home")
        .tempdir()
        .unwrap()
}

fn list_pods(limits: RunpodctlLimits) -> RunpodctlInvocation {
    RunpodctlInvocation::new(RunPodCommand::ListPods, limits)
}

fn key() -> SecretValue {
    SecretValue::new(KEY.as_bytes().to_vec())
}

/// Not a test of its own: the helper process the tests below start, which acts by
/// [`HELPER_MODE`] and does nothing when run as a plain test.
#[test]
#[ignore = "helper process for the runpodctl process-port tests"]
fn runpodctl_helper_process() {
    match std::env::var(HELPER_MODE).as_deref() {
        Ok("flood") => {
            let chunk = vec![b'x'; 64 * 1024];
            let started = Instant::now();
            let mut out = std::io::stdout().lock();
            while started.elapsed() < Duration::from_secs(30) {
                if out.write_all(&chunk).is_err() {
                    break;
                }
            }
        }
        Ok("sleep") => std::thread::sleep(Duration::from_secs(30)),
        Ok("answer") => {
            let _ = std::io::stdout().lock().write_all(b"[]");
            let _ = std::io::stderr().lock().write_all(b"note\n");
            std::process::exit(3);
        }
        _ => {}
    }
}

/// The helper started in `mode`, outside the port, so its mode variable survives.
fn helper(mode: &str) -> std::process::Child {
    let name = format!(
        "{}::runpodctl_helper_process",
        module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, rest)| rest)
    );
    Command::new(this_executable())
        .args([
            "--exact",
            &name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ])
        .env(HELPER_MODE, mode)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn the_program_must_be_an_absolute_local_exe_and_the_home_an_existing_directory() {
    let home = temporary_directory();
    assert_eq!(
        ProcessRunpodctl::new("runpodctl.exe", home.path()).unwrap_err(),
        RunpodctlRefusal::ProgramNotAbsolute
    );
    assert_eq!(
        ProcessRunpodctl::new(this_executable(), "relative-home").unwrap_err(),
        RunpodctlRefusal::HomeNotAbsolute
    );
    assert_eq!(
        ProcessRunpodctl::new(this_executable(), home.path().join("missing")).unwrap_err(),
        RunpodctlRefusal::HomeMissing
    );
    assert_eq!(
        ProcessRunpodctl::new(this_executable(), this_executable()).unwrap_err(),
        RunpodctlRefusal::HomeNotADirectory
    );
    #[cfg(windows)]
    {
        let script = home.path().join("runpodctl.bat");
        assert_eq!(
            ProcessRunpodctl::new(&script, home.path()).unwrap_err(),
            RunpodctlRefusal::ProgramNotExe
        );
        assert_eq!(
            ProcessRunpodctl::new(r"\\server\share\runpodctl.exe", home.path()).unwrap_err(),
            RunpodctlRefusal::ProgramNotOnLocalDrive
        );
        assert_eq!(
            ProcessRunpodctl::new(this_executable(), r"\\server\share\home").unwrap_err(),
            RunpodctlRefusal::HomeNotOnLocalDrive
        );
    }
    let port = ProcessRunpodctl::new(this_executable(), home.path()).unwrap();
    assert_eq!(port.program(), this_executable());
    assert_eq!(port.home(), home.path());
    assert_eq!(port.last_refusal(), None);
}

#[test]
fn the_command_holds_exactly_the_argv_and_the_key_only_in_a_cleared_environment() {
    let home = temporary_directory();
    let port = ProcessRunpodctl::new(this_executable(), home.path()).unwrap();
    let invocation = list_pods(RunpodctlLimits::QUERY);
    let command = port.command(&invocation, KEY);
    assert_eq!(command.get_program(), this_executable().as_os_str());
    let arguments: Vec<&OsStr> = command.get_args().collect();
    assert_eq!(
        arguments,
        invocation
            .arguments()
            .iter()
            .map(OsStr::new)
            .collect::<Vec<_>>()
    );
    for argument in &arguments {
        assert_eq!(
            find_encoded(argument.to_string_lossy().as_bytes(), KEY.as_bytes()),
            None
        );
    }
    assert_eq!(command.get_current_dir(), Some(home.path()));
    let mut expected: Vec<(String, String)> = INHERITED_ENVIRONMENT
        .iter()
        .filter_map(|name| {
            std::env::var(name)
                .ok()
                .map(|value| ((*name).to_owned(), value))
        })
        .collect();
    expected.extend(
        FIXED_ENVIRONMENT
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    expected.push((
        HOME_VARIABLE.to_owned(),
        home.path().to_string_lossy().into_owned(),
    ));
    expected.push((API_KEY_VARIABLE.to_owned(), KEY.to_owned()));
    expected.sort();
    let mut set: Vec<(String, String)> = command
        .get_envs()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.unwrap().to_string_lossy().into_owned(),
            )
        })
        .collect();
    set.sort();
    assert_eq!(set, expected);
    #[cfg(windows)]
    assert_eq!(INHERITED_ENVIRONMENT, ["SystemRoot"]);
}

#[test]
fn the_port_starts_the_configured_program_with_a_cleared_environment_and_reports_its_end() {
    let home = temporary_directory();
    let mut port = ProcessRunpodctl::new(this_executable(), home.path()).unwrap();
    // libtest refuses runpodctl's arguments: a real start, a real exit and real output.
    let output = port.run(&list_pods(RunpodctlLimits::QUERY), &key());
    assert_eq!(port.last_refusal(), None);
    assert!(
        matches!(output.termination, SshTermination::Exited { code } if code != 0),
        "{:?}",
        output.termination
    );
    assert!(!output.stderr.is_empty());
    assert_eq!(find_encoded(&output.stdout, KEY.as_bytes()), None);
    assert_eq!(find_encoded(&output.stderr, KEY.as_bytes()), None);
}

#[test]
fn a_missing_program_a_vanished_home_or_an_unusable_key_starts_nothing() {
    let home = temporary_directory();
    let missing = home.path().join("absent-runpodctl.exe");
    let mut port = ProcessRunpodctl::new(&missing, home.path()).unwrap();
    let output = port.run(&list_pods(RunpodctlLimits::QUERY), &key());
    assert_eq!(output.termination, SshTermination::NotStarted);
    assert!(matches!(
        port.last_refusal(),
        Some(RunpodctlRefusal::StartFailed { .. })
    ));
    let mut port = ProcessRunpodctl::new(this_executable(), home.path()).unwrap();
    let output = port.run(
        &list_pods(RunpodctlLimits::QUERY),
        &SecretValue::new(b"key with spaces".to_vec()),
    );
    assert_eq!(output.termination, SshTermination::NotStarted);
    assert_eq!(port.last_refusal(), Some(&RunpodctlRefusal::KeyNotText));
    assert!(
        !format!("{:?} {}", port.last_refusal(), RunpodctlRefusal::KeyNotText).contains("spaces")
    );
    let gone = temporary_directory();
    let mut port = ProcessRunpodctl::new(this_executable(), gone.path()).unwrap();
    drop(gone);
    let output = port.run(&list_pods(RunpodctlLimits::QUERY), &key());
    assert_eq!(output.termination, SshTermination::NotStarted);
    assert_eq!(port.last_refusal(), Some(&RunpodctlRefusal::HomeMissing));
}

#[test]
fn an_answer_is_read_whole_with_its_exit_status() {
    let limits = RunpodctlLimits::new(Duration::from_secs(60), 1024, 1024).unwrap();
    let output = supervise(helper("answer"), limits, Instant::now());
    assert_eq!(output.termination, SshTermination::Exited { code: 3 });
    // libtest prints its own header first; the helper's answer follows it.
    assert!(output.stdout.ends_with(b"[]"), "{:?}", output.stdout);
    assert!(output.stderr.windows(4).any(|part| part == b"note"));
}

#[test]
fn runpodctl_still_running_at_its_deadline_is_killed() {
    let limits = RunpodctlLimits::new(Duration::from_secs(3), 1024, 1024).unwrap();
    let started = Instant::now();
    let output = supervise(helper("sleep"), limits, started);
    assert_eq!(output.termination, SshTermination::DeadlineReached);
    assert!(started.elapsed() < Duration::from_secs(3) + REAP_WAIT + Duration::from_secs(5));
}

#[test]
fn runpodctl_passing_an_output_bound_is_killed_with_the_stream_one_byte_over() {
    let limits = RunpodctlLimits::new(Duration::from_secs(60), 64 * 1024, 1024).unwrap();
    let started = Instant::now();
    let output = supervise(helper("flood"), limits, started);
    assert_eq!(output.stdout.len(), 64 * 1024 + 1);
    assert!(matches!(
        output.termination,
        SshTermination::NoExitStatus | SshTermination::Exited { .. }
    ));
    assert!(started.elapsed() < Duration::from_secs(25));
}
