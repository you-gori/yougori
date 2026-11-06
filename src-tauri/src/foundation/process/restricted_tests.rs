//! Tests of the restricted start (M02, M04): the flag mappings, the refusals made before
//! anything is created, and real starts of this test executable as the helper of
//! `foundation::process::tests` (it sleeps or exits), whose restrictions are read back
//! through the handles the host holds. Every helper runs in a kill-on-close job, so
//! nothing outlives the test; no network is touched.

use std::collections::BTreeSet;
use std::process::Command;
use std::time::Duration;

use super::*;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{digest, ExecutionId, SandboxBootGeneration};
use crate::foundation::process::{Escalation, HostProcess, ProcessRole, SandboxDesktop};

const GIB: u64 = 1 << 30;

/// This test executable, set to run only `foundation::process::tests::helper_process`
/// in `mode`, with only the variables a restricted start needs.
fn helper(mode: &str) -> Command {
    let path = module_path!();
    let tests = path.split_once("::").map_or(path, |(_, rest)| rest);
    let tests = tests.replace("restricted::tests", "tests");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            &format!("{tests}::helper_process"),
            "--test-threads=1",
            "--quiet",
        ])
        .env("YG_PROCESS_HELPER", mode)
        .env("SystemRoot", std::env::var("SystemRoot").unwrap());
    command
}

fn role() -> ProcessRole {
    let execution = ExecutionId::new("restricted-test").unwrap();
    ProcessRole::VmHost {
        vm: VmInstanceId::new(digest("yougori/test/vm/v1", &[b"restricted"])),
        boot: SandboxBootGeneration::new(1),
        execution,
    }
}

/// A desktop of this test process and line, so parallel starts never collide.
fn station(line: u32) -> SandboxDesktop {
    SandboxDesktop::for_start(
        &format!("ygs{}-{line}", std::process::id()),
        &groups(),
        LoweredIntegrity::Low,
    )
    .unwrap()
}

fn groups() -> BTreeSet<RestrictingGroup> {
    [
        RestrictingGroup::Users,
        RestrictingGroup::Everyone,
        RestrictingGroup::Restricted,
        RestrictingGroup::LogonSession,
        RestrictingGroup::AuthenticatedUsers,
    ]
    .into_iter()
    .collect()
}

fn start_at(line: u32, stderr: Option<std::fs::File>) -> RestrictedStart {
    RestrictedStart {
        restricting: groups(),
        integrity: LoweredIntegrity::Low,
        job: JobSettings {
            active_process_limit: 1,
            job_memory_limit_bytes: 2 * GIB,
            die_on_unhandled_exception: true,
            ui_restrictions: true,
        },
        mitigations: StartMitigation::ALL.into_iter().collect(),
        stderr,
        desktop: station(line),
    }
}

fn escalation() -> Escalation {
    Escalation {
        grace: Duration::ZERO,
        kill_wait: Duration::from_secs(20),
    }
}

#[test]
fn mitigation_flags_are_the_always_on_creation_bits() {
    let all: BTreeSet<StartMitigation> = StartMitigation::ALL.into_iter().collect();
    assert_eq!(
        mitigation_flags(&all),
        (1 << 24) | (1 << 32) | (1 << 52) | (1 << 56)
    );
    assert_eq!(mitigation_flags(&BTreeSet::new()), 0);
}

#[test]
fn policy_words_map_to_the_mitigations_in_effect() {
    assert_eq!(mitigations_from_words(0b11, 1, 0b11).len(), 4);
    // Strict handle checks count only when both bits are set.
    assert!(!mitigations_from_words(0b01, 0, 0).contains(&StartMitigation::StrictHandleChecks));
    assert_eq!(
        mitigations_from_words(0, 0, 0b10),
        [StartMitigation::ImageLoadNoLowLabel].into_iter().collect()
    );
}

#[test]
fn job_settings_set_kill_on_close_and_never_breakaway() {
    let settings = start_at(line!(), None).job;
    let flags = settings.limit_flags();
    assert_ne!(flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0);
    assert_ne!(flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS, 0);
    assert_ne!(flags & JOB_OBJECT_LIMIT_JOB_MEMORY, 0);
    assert_ne!(flags & JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, 0);
    assert_eq!(flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK, 0);
    assert_eq!(flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, 0);
    assert_eq!(settings.ui_class(), 0xFF);
}

#[test]
fn a_relative_program_no_restricting_sid_or_zero_limits_are_refused_before_any_start() {
    let refused = |command: &Command, start: &mut RestrictedStart| {
        matches!(
            create_restricted_suspended(command, start),
            Err(ProcessError::Spawn { .. })
        )
    };
    let mut relative = start_at(line!(), None);
    assert!(refused(&Command::new("relative.exe"), &mut relative));
    let mut none = start_at(line!(), None);
    none.restricting.clear();
    assert!(refused(&helper("sleep"), &mut none));
    let mut zero = start_at(line!(), None);
    zero.job.active_process_limit = 0;
    assert!(refused(&helper("sleep"), &mut zero));
    let mut no_memory = start_at(line!(), None);
    no_memory.job.job_memory_limit_bytes = 0;
    assert!(refused(&helper("sleep"), &mut no_memory));
}

#[test]
fn a_command_line_splits_back_into_its_arguments() {
    let line: Vec<u16> =
        r#""C:\a b\q.exe" -name x "two words" a\"b"#.encode_utf16().chain([0]).collect();
    assert_eq!(
        split_command_line(&line).unwrap(),
        vec![r"C:\a b\q.exe", "-name", "x", "two words", r#"a"b"#]
    );
}

#[test]
fn a_restricted_start_runs_low_restricted_in_its_job_with_what_was_asked_in_effect() {
    let command = helper("sleep");
    let (process, seen) = HostProcess::spawn_restricted(&command, role(), start_at(line!(), None))
        .expect("restricted start");
    let readback = process.read_restrictions().expect("read back");
    assert!(readback.token_restricted);
    assert_eq!(
        readback.restricting,
        [
            ObservedGroup::Users,
            ObservedGroup::Everyone,
            ObservedGroup::Restricted,
            ObservedGroup::LogonSession,
            ObservedGroup::AuthenticatedUsers
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        readback.privileges,
        ["SeChangeNotifyPrivilege".to_owned()].into_iter().collect()
    );
    assert_ne!(readback.administrators, AdministratorsState::Enabled);
    assert_eq!(readback.integrity_rid, LoweredIntegrity::Low.rid());
    assert!(readback.in_job);
    assert!(readback.job.kill_on_close);
    assert!(readback.job.die_on_unhandled_exception);
    assert!(!readback.job.breakaway_ok && !readback.job.silent_breakaway_ok);
    assert_eq!(readback.job.active_process_limit, 1);
    assert_eq!(readback.job.job_memory_limit_bytes, 2 * GIB);
    assert_eq!(readback.job.ui_restrictions, 0xFF);
    assert_eq!(
        readback.mitigations,
        StartMitigation::ALL.into_iter().collect()
    );
    let expected: Vec<String> = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|part| part.to_string_lossy().into_owned())
        .collect();
    assert_eq!(readback.command_line, expected);
    assert_eq!(seen.listed_handles, 1);
    assert!(!seen.stderr_logged);
    assert!(
        seen.handles_at_start <= seen.listed_handles,
        "{seen:?}: a suspended process holds only what it inherited"
    );
    let proof = process.terminate(escalation()).expect("termination proof");
    assert_eq!(proof.identity(), process.identity());
}

#[test]
fn a_restricted_start_passes_its_log_file_as_standard_error_only() {
    let directory =
        std::env::temp_dir().join(format!("yg-restricted-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&directory).unwrap();
    let log = std::fs::File::create(directory.join("stderr.log")).unwrap();
    let (process, seen) =
        HostProcess::spawn_restricted(&helper("exit:0"), role(), start_at(line!(), Some(log)))
            .expect("restricted start");
    assert_eq!(seen.listed_handles, 2);
    assert!(seen.stderr_logged);
    assert!(seen.handles_at_start <= seen.listed_handles, "{seen:?}");
    let proof = process
        .wait_ended(Duration::from_secs(20))
        .expect("the helper exits");
    assert_eq!(proof.identity(), process.identity());
    assert_eq!(proof.exit_code(), 0, "the helper ran: {proof:?}");
    assert_eq!(
        proof.job_processes(),
        1,
        "no console host or other process joined the job: {proof:?}"
    );
    drop(process);
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn the_active_process_limit_stops_a_restricted_process_starting_another() {
    let (process, _) =
        HostProcess::spawn_restricted(&helper("grandchild"), role(), start_at(line!(), None))
            .expect("restricted start");
    let proof = process
        .wait_ended(Duration::from_secs(20))
        .expect("the helper exits");
    // The helper exits with 2 when its own start of another copy fails: the job's active
    // process limit is one. A helper that died before its own code ran (`0xC0000142`)
    // would say the restricted start cannot run this program at all.
    assert_eq!(proof.exit_code(), 2, "{proof:?}");
}

/// The Windows Hypervisor Platform's capability report as a token variant sees it, for
/// [`whpx_capability_under_token_variants`]. `spec` is `il=own|keep|low|medium|untrusted;
/// sids=<comma list of users, everyone, restricted, logon, authenticated, interactive>`:
/// `own` calls with this process's own token; every other value builds a restricted token
/// as the production start does (Administrators deny-only, `DISABLE_MAX_PRIVILEGE`, the
/// restricting SIDs named, the label named or kept) and impersonates it on this thread for
/// the one call. Returns the helper's exit code (0 present, 10 absent, 11 library missing,
/// 12 the call failed, 20 the token could not be made, 21 impersonation failed) and a note.
/// Runs `probe` on this thread under the token variant `spec` names
/// (`il=own|keep|low|medium|untrusted;sids=users,everyone,restricted,logon,authenticated,interactive`):
/// a restricted copy of the process token with Administrators deny-only, no privileges and
/// the named restricting SIDs, at the named label (`keep` leaves the label), impersonated
/// for the probe's duration; `own` runs the probe on the process token itself. The exit
/// code is the probe's, or 20 when the token could not be made and 21 when it could not be
/// impersonated; the note names the variant and the probe's word.
pub(crate) fn under_token_variant(spec: &str, probe: &dyn Fn() -> (i32, String)) -> (i32, String) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::{
        ImpersonateLoggedOnUser, RevertToSelf, WinAuthenticatedUserSid, WinInteractiveSid,
        WinMediumLabelSid,
    };

    let mut integrity = "low";
    let mut names: Vec<&str> = Vec::new();
    for part in spec.split(';') {
        if let Some(value) = part.strip_prefix("il=") {
            integrity = value;
        } else if let Some(value) = part.strip_prefix("sids=") {
            names = value.split(',').filter(|name| !name.is_empty()).collect();
        }
    }
    if integrity == "own" {
        let (code, note) = probe();
        return (code, format!("own token: {note}"));
    }
    let Ok(own) = own_token() else {
        return (20, "own token unavailable".to_owned());
    };
    let Ok(logon) = logon_sid(own.as_raw_handle()) else {
        return (20, "logon SID unavailable".to_owned());
    };
    let Ok(administrators) = well_known(WinBuiltinAdministratorsSid, "Administrators") else {
        return (20, "Administrators SID unavailable".to_owned());
    };
    let mut keep: Vec<Sid> = Vec::new();
    for name in &names {
        let kind = match *name {
            "users" => WinBuiltinUsersSid,
            "everyone" => WinWorldSid,
            "restricted" => WinRestrictedCodeSid,
            "authenticated" => WinAuthenticatedUserSid,
            "interactive" => WinInteractiveSid,
            "logon" => continue,
            other => return (20, format!("unknown SID name {other}")),
        };
        match well_known(kind, name) {
            Ok(sid) => keep.push(sid),
            Err(_) => return (20, format!("SID {name} unavailable")),
        }
    }
    let mut restricting: Vec<SID_AND_ATTRIBUTES> = keep
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.as_psid(),
            Attributes: 0,
        })
        .collect();
    if names.contains(&"logon") {
        restricting.push(SID_AND_ATTRIBUTES {
            Sid: logon.as_psid(),
            Attributes: 0,
        });
    }
    let disable = [SID_AND_ATTRIBUTES {
        Sid: administrators.as_psid(),
        Attributes: 0,
    }];
    let mut token: HANDLE = null_mut();
    // SAFETY: the source token is open with duplicate access; every SID is live for the
    // call; `token` is live.
    let made = unsafe {
        CreateRestrictedToken(
            own.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            1,
            disable.as_ptr(),
            0,
            null(),
            u32::try_from(restricting.len()).unwrap_or(0),
            if restricting.is_empty() {
                null()
            } else {
                restricting.as_ptr()
            },
            &mut token,
        )
    };
    if made == 0 {
        return (
            20,
            format!("CreateRestrictedToken failed: {}", last_error()),
        );
    }
    let Some(token) = owned(token) else {
        return (20, "token handle invalid".to_owned());
    };
    let label_kind = match integrity {
        "low" => Some(WinLowLabelSid),
        "medium" => Some(WinMediumLabelSid),
        "untrusted" => Some(WinUntrustedLabelSid),
        "keep" => None,
        other => return (20, format!("unknown integrity {other}")),
    };
    if let Some(kind) = label_kind {
        let Ok(label) = well_known(kind, "mandatory label") else {
            return (20, "label SID unavailable".to_owned());
        };
        let mandatory = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: label.as_psid(),
                Attributes: SE_GROUP_INTEGRITY,
            },
        };
        let size = u32::try_from(std::mem::size_of::<TOKEN_MANDATORY_LABEL>())
            .unwrap_or(0)
            .saturating_add(label.length());
        // SAFETY: the token is open with adjust-default access; the label and its SID are live.
        let set = unsafe {
            SetTokenInformation(
                token.as_raw_handle(),
                TokenIntegrityLevel,
                (&mandatory as *const TOKEN_MANDATORY_LABEL).cast(),
                size,
            )
        };
        if set == 0 {
            return (
                20,
                format!("SetTokenInformation(label) failed: {}", last_error()),
            );
        }
    }
    // SAFETY: the token is a valid primary token; impersonation is reverted below.
    let impersonated = unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) };
    if impersonated == 0 {
        return (
            21,
            format!("ImpersonateLoggedOnUser failed: {}", last_error()),
        );
    }
    let (code, note) = probe();
    // SAFETY: reverts this thread's impersonation.
    unsafe { RevertToSelf() };
    (
        code,
        format!("il={integrity} sids={}: {note}", names.join(",")),
    )
}

/// The Windows Hypervisor Platform's capability report under the token variant `spec`
/// (0 present, 10 absent, 11 library missing, 12 call failed).
pub(crate) fn whpx_capability_as(spec: &str) -> (i32, String) {
    use crate::sandbox_vm::probes::{platform_report, PlatformReport};
    under_token_variant(spec, &|| {
        let report = platform_report();
        let code = match report {
            PlatformReport::Present => 0,
            PlatformReport::Absent => 10,
            PlatformReport::LibraryMissing => 11,
            PlatformReport::CallFailed { .. } => 12,
            // Linux's reports; never made on Windows.
            PlatformReport::DeviceMissing
            | PlatformReport::DeviceUnusable { .. }
            | PlatformReport::UnexpectedApi { .. } => 13,
        };
        (code, format!("{report:?}"))
    })
}

/// The Credential Manager's answer for the entry `service`/`user` under the token variant
/// `spec` (0 read, 10 no entry, 12 refused): what the sandbox executor's vault store needs.
pub(crate) fn credential_read_as(spec: &str, service: &str, user: &str) -> (i32, String) {
    under_token_variant(spec, &|| match keyring::Entry::new(service, user)
        .and_then(|entry| entry.get_password())
    {
        Ok(_) => (0, "credential read".to_owned()),
        Err(keyring::Error::NoEntry) => (10, "no entry".to_owned()),
        Err(error) => (12, format!("refused: {error}")),
    })
}

/// Whether the named pipe `name`, which the caller created, opens for reading and writing
/// under the token variant `spec` (0 opened, 12 refused): what the executor's control pipe
/// and the relays' link pipes need.
pub(crate) fn pipe_open_as(spec: &str, name: &str) -> (i32, String) {
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    };
    under_token_variant(spec, &|| {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: `wide` is a NUL-terminated name; no security attributes or template.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            (12, format!("open refused: OS error {}", last_error()))
        } else {
            drop(owned(raw));
            (0, "pipe opened".to_owned())
        }
    })
}

/// DIAGNOSTIC of 30 October 2026 for the restricted sandbox executor (VM-W26, VM-W28): the
/// executor must read the OS credential store and open the engine's owner-only control
/// pipe. Each variant impersonates a restricted token on this thread and reads a fixture
/// entry (written by this test under the service `Yougori.SandboxVault.Diagnostic`, removed
/// after) and opens a fresh owner-only pipe, so the table says which token parts the
/// executor's needs survive: the restricting SIDs, the lowered label, or neither.
#[test]
#[ignore = "writes and removes a Credential Manager fixture entry and reads it under token variants; run with --ignored --nocapture"]
fn executor_needs_under_token_variants() {
    use crate::sandbox_contract::relay_link::control_pipe::ControlListener;
    use crate::sandbox_contract::relay_link::RelayPipeName;

    const SERVICE: &str = "Yougori.SandboxVault.Diagnostic";
    const USER: &str = "probe";
    let entry = keyring::Entry::new(SERVICE, USER).unwrap();
    entry.set_password("fixture-not-a-secret").unwrap();
    let variants = [
        ("own token", "il=own;sids="),
        (
            "restricting users+everyone+restricted+logon+authenticated, label kept",
            "il=keep;sids=users,everyone,restricted,logon,authenticated",
        ),
        (
            "restricting users+everyone+restricted+logon, label kept",
            "il=keep;sids=users,everyone,restricted,logon",
        ),
        (
            "restricting users+everyone+restricted+logon+authenticated, medium",
            "il=medium;sids=users,everyone,restricted,logon,authenticated",
        ),
        (
            "restricting users+everyone+restricted+logon+authenticated, low",
            "il=low;sids=users,everyone,restricted,logon,authenticated",
        ),
        ("no restricting SID, low", "il=low;sids="),
        (
            "no restricting SID, label kept (privileges off)",
            "il=keep;sids=",
        ),
    ];
    for (title, spec) in variants {
        let name = format!(
            r"\\.\pipe\yougori-executor-diag-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        );
        let listener = ControlListener::create(RelayPipeName::new(name.clone()).unwrap()).unwrap();
        let (credential_code, credential_note) = credential_read_as(spec, SERVICE, USER);
        let (pipe_code, pipe_note) = pipe_open_as(spec, &name);
        drop(listener);
        eprintln!(
            "EXECUTOR {title:72} credential exit {credential_code:>3} ({credential_note}) | owner-only pipe exit {pipe_code:>3} ({pipe_note})"
        );
    }
    let _ = entry.delete_credential();
}

/// DIAGNOSTIC of 30 October 2026: the restricted QEMU was refused by the Windows
/// Hypervisor Platform (`WHvGetCapability` returned `E_ACCESSDENIED`, QEMU's "No
/// accelerator found, hr=80070005"). Each variant runs the helper once in a fresh process
/// (the platform library caches its device handle), so the table says which part of the
/// restricted token the platform refuses: the lowered label, the restricting SIDs, or both.
#[test]
#[ignore = "asks the Windows Hypervisor Platform for its capability under token variants; run with --ignored --nocapture"]
fn whpx_capability_under_token_variants() {
    let variants = [
        ("own token", "il=own;sids="),
        (
            "profile: low, users+everyone+restricted+logon",
            "il=low;sids=users,everyone,restricted,logon",
        ),
        (
            "medium, users+everyone+restricted+logon",
            "il=medium;sids=users,everyone,restricted,logon",
        ),
        (
            "kept label, users+everyone+restricted+logon",
            "il=keep;sids=users,everyone,restricted,logon",
        ),
        ("low, no restricting SIDs", "il=low;sids="),
        ("medium, no restricting SIDs", "il=medium;sids="),
        ("kept label, no restricting SIDs", "il=keep;sids="),
        (
            "low, profile + authenticated users",
            "il=low;sids=users,everyone,restricted,logon,authenticated",
        ),
        (
            "medium, profile + authenticated users",
            "il=medium;sids=users,everyone,restricted,logon,authenticated",
        ),
        (
            "low, profile + interactive",
            "il=low;sids=users,everyone,restricted,logon,interactive",
        ),
        ("medium, users only", "il=medium;sids=users"),
        ("medium, everyone only", "il=medium;sids=everyone"),
        ("medium, restricted only", "il=medium;sids=restricted"),
        ("medium, logon only", "il=medium;sids=logon"),
        ("medium, authenticated only", "il=medium;sids=authenticated"),
    ];
    for (name, spec) in variants {
        let output = helper(&format!("whpx:{spec}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();
        eprintln!(
            "WHPX {name:48} exit {:>3} {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
}
