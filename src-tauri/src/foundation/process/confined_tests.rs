//! Tests of the parts of a confined start that need no AppContainer (M09E): the command
//! line read back through `CommandLineToArgvW`, the environment block, the AppContainer
//! SID check and the refusals made before any process is created. No process is started
//! here: a real confined start creates an AppContainer profile in the user's profile, and
//! `sandbox_contract::relay_process`'s launch tests do that, with guards that remove it.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::process::Command;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

use super::{command_line, create_suspended, environment, Confinement};
use crate::foundation::process::ProcessError;

/// `line` (NUL-terminated) as `CommandLineToArgvW` splits it.
fn split(line: &[u16]) -> Vec<String> {
    let mut count = 0_i32;
    let argv = unsafe { CommandLineToArgvW(line.as_ptr(), &mut count) };
    assert!(!argv.is_null());
    let arguments = (0..usize::try_from(count).unwrap())
        .map(|index| unsafe {
            let argument = *argv.add(index);
            let length = (0..).take_while(|&at| *argument.add(at) != 0).count();
            OsString::from_wide(std::slice::from_raw_parts(argument, length))
                .into_string()
                .unwrap()
        })
        .collect();
    unsafe { LocalFree(argv.cast()) };
    arguments
}

/// An AppContainer SID, S-1-15-2-1-2-3-4-5-6-7, in its binary form.
fn app_container_sid() -> Vec<u8> {
    let mut sid = vec![1, 8, 0, 0, 0, 0, 0, 15];
    for sub_authority in [2_u32, 1, 2, 3, 4, 5, 6, 7] {
        sid.extend_from_slice(&sub_authority.to_le_bytes());
    }
    sid
}

fn refusal(result: Result<impl std::fmt::Debug, ProcessError>) -> String {
    match result {
        Err(ProcessError::Spawn { detail }) => detail,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_command_line_reads_back_through_command_line_to_argv() {
    let program = r"C:\Program Files\Yougori\sandbox host.exe";
    let arguments = [
        "relay",
        "",
        "with space",
        "tab\there",
        "a \"quoted\" word",
        "\"",
        "trailing\\",
        "trailing space\\ ",
        "two\\\\",
        "backslash\\\"quote",
        "\\\\server\\share\\",
        "C:\\path with\\spaces\\",
        "--flag=value",
    ];
    let mut command = Command::new(program);
    command.args(arguments);
    let line = command_line(&command).unwrap();
    assert_eq!(line.last(), Some(&0), "NUL-terminated");
    let mut expected = vec![program.to_owned()];
    expected.extend(arguments.iter().map(|argument| (*argument).to_owned()));
    assert_eq!(split(&line), expected);
    // No argument at all.
    assert_eq!(
        split(&command_line(&Command::new(program)).unwrap()),
        vec![program]
    );
}

#[test]
fn the_environment_is_only_what_the_command_sets_sorted_and_double_nul_terminated() {
    let mut command = Command::new(r"C:\relay.exe");
    command
        .env_clear()
        .env("b", "2")
        .env("LOCALAPPDATA", "none")
        .env("A", "1")
        .env("removed", "x")
        .env_remove("removed");
    let block = environment(&command).unwrap();
    let expected: Vec<u16> = "A=1\0b=2\0LOCALAPPDATA=none\0\0".encode_utf16().collect();
    assert_eq!(block, expected);
    // Nothing set: the empty block is two NULs, with nothing of this process's.
    assert_eq!(
        environment(&Command::new(r"C:\relay.exe")).unwrap(),
        vec![0, 0]
    );
    let mut cleared = Command::new(r"C:\relay.exe");
    cleared.env_clear();
    assert_eq!(environment(&cleared).unwrap(), vec![0, 0]);
}

#[test]
fn an_environment_name_with_an_equals_sign_or_none_or_a_nul_is_refused() {
    for (name, value) in [("A=B", "1"), ("", "1"), ("A", "1\u{0}2"), ("A\u{0}B", "1")] {
        let mut command = Command::new(r"C:\relay.exe");
        command.env_clear().env(name, value);
        refusal(environment(&command));
    }
}

#[test]
fn only_an_appcontainer_sid_of_exactly_its_length_is_accepted() {
    assert!(Confinement::app_container(&app_container_sid()).is_ok());
    let valid = |sid: &[u8]| refusal(Confinement::app_container(sid));
    // Short and long.
    assert!(valid(&[1, 0, 0, 0, 0, 0, 0]).contains("not a valid SID"));
    assert!(valid(&[0; 69]).contains("not a valid SID"));
    // Invalid: revision 2.
    let mut revision = app_container_sid();
    revision[0] = 2;
    assert!(valid(&revision).contains("not a valid SID"));
    // Length mismatch: a byte cut off, a byte added, a count above what is given.
    let sid = app_container_sid();
    assert!(valid(&sid[..sid.len() - 4]).contains("not a valid SID"));
    let mut longer = sid.clone();
    longer.extend_from_slice(&[0; 4]);
    assert!(valid(&longer).contains("not a valid SID"));
    let mut count = sid.clone();
    count[1] = 9;
    assert!(valid(&count).contains("not a valid SID"));
    // Valid SIDs that are not AppContainer SIDs: Everyone (S-1-1-0), a capability
    // (S-1-15-3-1) and the bare package authority (S-1-15).
    let everyone = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    assert!(valid(&everyone).contains("not an AppContainer SID"));
    let capability = [1, 2, 0, 0, 0, 0, 0, 15, 3, 0, 0, 0, 1, 0, 0, 0];
    assert!(valid(&capability).contains("not an AppContainer SID"));
    let bare = [1, 0, 0, 0, 0, 0, 0, 15];
    assert!(valid(&bare).contains("not an AppContainer SID"));
}

#[test]
fn a_relative_program_a_nul_or_a_quote_in_the_program_is_refused_before_any_start() {
    let confinement = Confinement::app_container(&app_container_sid()).unwrap();
    let start = |command: &Command| refusal(create_suspended(command, &confinement));
    let mut local = Command::new("relay.exe");
    local.env("LOCALAPPDATA", "none");
    assert!(start(&local).contains("absolute path"));
    let mut nul = Command::new("C:\\relay\u{0}.exe");
    nul.env("LOCALAPPDATA", "none");
    assert!(start(&nul).contains("NUL"));
    let mut nul_argument = Command::new(r"C:\relay.exe");
    nul_argument.arg("a\u{0}b").env("LOCALAPPDATA", "none");
    assert!(start(&nul_argument).contains("NUL"));
    let mut quote = Command::new("C:\\re\"lay\\relay.exe");
    quote.env("LOCALAPPDATA", "none");
    assert!(start(&quote).contains("quote"));
}
