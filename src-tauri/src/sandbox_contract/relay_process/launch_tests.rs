//! Tests of the confined launch on Windows (M09E). The only processes started are this
//! test executable again: confined by [`launch_relay`], running one of the
//! `confined_helper_*` tests, each of which does nothing unless it finds itself confined;
//! and, unconfined, [`impostor_helper`], which does nothing without its variable. Every
//! process runs in a kill-on-close job held by the test, every launch is ended (or dropped,
//! which ends it) so its AppContainer profile and executable grant are removed, also on
//! failure. Pipes have unique names. No network is touched.
//!
//! The launch tests are `#[ignore]`d by default: each creates and removes an AppContainer
//! profile and an ACL grant in the user's profile. Run them on a Windows host with
//! `cargo test --lib relay_process -- --ignored`.

use std::ffi::OsString;
use std::io::Read;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::{Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CompareObjectHandles, DuplicateHandle, LocalFree, DUPLICATE_SAME_ACCESS, ERROR_SUCCESS,
};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, GetSecurityInfo, SE_FILE_OBJECT, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, FreeSid, GetAce, GetAclInformation, ACCESS_ALLOWED_ACE, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, PSID,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, READ_CONTROL};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::*;
use crate::foundation::ids::ExecutionId;
use crate::foundation::process::{
    Ending, Escalation, HostProcess, ProcessIdentity, ProcessRole, KILLED_EXIT_CODE,
};
use crate::sandbox_contract::destinations::RouteId;
use crate::sandbox_contract::relay::ReaderLimits;
use crate::sandbox_contract::relay_link::{
    open_confined_relay, BrokerMessage, BrokerSide, CloseReason, ExchangeId, LinkBinding, LinkKey,
    LinkPipe, LinkRefusal, LinkSessionId, PeerRefusal, PipeError, RelayMessage, RelayPipeListener,
    RelayPipeName, WireBytes, CONTAINER_PIPE_ACCESS,
};

/// The variable that makes this executable the unconfined impostor.
const IMPOSTOR: &str = "YG_RELAY_PROCESS_IMPOSTOR";

/// The prefix of a helper's one argument, passed as an extra test filter that matches no
/// test.
const ARGUMENT: &str = "yg-relay-arg=";

/// How long a helper may take: a whole test executable starts, confined.
const PATIENT: Duration = Duration::from_secs(30);

/// How long the late relay waits before it reads its handoff.
const LATE: Duration = Duration::from_secs(3);

const ENDPOINT: &str = "provider";
const ROUTE: &str = "provider-api";

const REQUEST: &[u8] =
    b"GET /v1/models?limit=2 HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\n\r\n";
const FORWARDED: &[u8] =
    b"GET /v1/models?limit=2 HTTP/1.1\r\nhost: api.example.com\r\naccept: application/json\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";

/// Exit codes of the helpers beyond [`RelayExit::code`].
const WRONG_RESPONSE: i32 = 20;
const OPENED: i32 = 31;
const OTHER_ERROR: i32 = 32;
const NO_ARGUMENT: i32 = 33;

fn routes() -> RouteTable {
    RouteTable::new(vec![RouteEntry {
        endpoint: GuestEndpoint::new(ENDPOINT).unwrap(),
        route: RouteId::new(ROUTE).unwrap(),
    }])
    .unwrap()
}

fn limits() -> ReaderLimits {
    ReaderLimits::new(4_096, 65_536).unwrap()
}

/// A sandbox of its own for each test, so profiles never collide.
fn sandbox() -> ExecutionId {
    ExecutionId::new(format!("relay-test-{}", uuid::Uuid::new_v4().simple())).unwrap()
}

fn tests_path() -> String {
    let path = module_path!();
    path.split_once("::")
        .map_or(path, |(_, rest)| rest)
        .to_owned()
}

/// The arguments that run only `helper` of this executable, with an optional argument.
fn helper_arguments(helper: &str, argument: Option<&str>) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = vec![
        "--exact".into(),
        format!("{}::{helper}", tests_path()).into(),
        "--test-threads=1".into(),
        "--quiet".into(),
    ];
    if let Some(argument) = argument {
        arguments.push(format!("{ARGUMENT}{argument}").into());
    }
    arguments
}

/// The helper's argument, if it was given one.
fn helper_argument() -> Option<String> {
    std::env::args().find_map(|argument| argument.strip_prefix(ARGUMENT).map(str::to_owned))
}

/// Launches this executable confined, running `helper`.
fn launch(sandbox: &ExecutionId, helper: &str, argument: Option<&str>) -> LaunchedRelay {
    launch_relay(RelayLaunch {
        sandbox: sandbox.clone(),
        executable: std::env::current_exe().unwrap(),
        arguments: helper_arguments(helper, argument),
        routes: routes(),
        limits: limits(),
        guest_engine_pid: None,
    })
    .unwrap()
}

/// A guest that opens one connection to [`ENDPOINT`], sends [`REQUEST`], keeps what the
/// relay writes and ends once the relay ends the connection.
struct OneRequestGuest {
    step: u8,
    written: Arc<Mutex<Vec<u8>>>,
    ended: bool,
}

impl GuestPort for OneRequestGuest {
    fn next_event(&mut self, within: Duration) -> Result<GuestEvent, GuestPortError> {
        let connection = GuestConnection::new(1);
        self.step = self.step.saturating_add(1);
        Ok(match self.step {
            1 => GuestEvent::Opened {
                connection,
                endpoint: GuestEndpoint::new(ENDPOINT).unwrap(),
            },
            2 => GuestEvent::Data {
                connection,
                bytes: REQUEST.to_vec(),
            },
            _ if self.ended => GuestEvent::Ended,
            _ => {
                thread::sleep(within);
                GuestEvent::Idle
            }
        })
    }

    fn write(&mut self, _connection: GuestConnection, bytes: &[u8]) -> Result<(), GuestPortError> {
        self.written.lock().unwrap().extend_from_slice(bytes);
        Ok(())
    }

    fn end(&mut self, _connection: GuestConnection) {
        self.ended = true;
    }
}

/// Runs the relay from this process's handoff with a [`OneRequestGuest`] and exits with
/// its code, or [`WRONG_RESPONSE`] if the guest did not get [`RESPONSE`].
fn run_relay_helper(delay: Duration) -> ! {
    thread::sleep(delay);
    let written = Arc::new(Mutex::new(Vec::new()));
    let guest = OneRequestGuest {
        step: 0,
        written: Arc::clone(&written),
        ended: false,
    };
    let exit = relay_main(guest);
    let mut code = exit.code();
    if code == 0 && written.lock().unwrap().as_slice() != RESPONSE {
        code = WRONG_RESPONSE;
    }
    std::process::exit(code);
}

#[test]
fn confined_helper_relay() {
    if check_confined().is_ok() {
        run_relay_helper(Duration::ZERO);
    }
}

#[test]
fn confined_helper_late_relay() {
    if check_confined().is_ok() {
        run_relay_helper(LATE);
    }
}

#[test]
fn confined_helper_sleep() {
    if check_confined().is_ok() {
        thread::sleep(Duration::from_secs(120));
        std::process::exit(0);
    }
}

/// Tries to open the file named by its argument: 0 when access is denied.
#[test]
fn confined_helper_open_file() {
    if check_confined().is_err() {
        return;
    }
    let Some(path) = helper_argument() else {
        std::process::exit(NO_ARGUMENT);
    };
    std::process::exit(match std::fs::File::open(path) {
        Ok(_) => OPENED,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => 0,
        Err(_) => OTHER_ERROR,
    });
}

/// Tries to read the identity of the process whose PID is its argument: 0 when it
/// cannot.
#[test]
fn confined_helper_open_broker() {
    if check_confined().is_err() {
        return;
    }
    let Some(pid) = helper_argument().and_then(|pid| pid.parse::<u32>().ok()) else {
        std::process::exit(NO_ARGUMENT);
    };
    std::process::exit(match ProcessIdentity::holder_of(pid) {
        Ok(_) => OPENED,
        Err(_) => 0,
    });
}

/// The unconfined impostor: opens the pipe named by its variable, retrying until it
/// can, and holds it until the server drops it.
#[test]
fn impostor_helper() {
    let Ok(name) = std::env::var(IMPOSTOR) else {
        return;
    };
    let deadline = Instant::now() + PATIENT;
    let mut pipe = loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
        {
            Ok(pipe) => break pipe,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Err(_) => std::process::exit(OTHER_ERROR),
        }
    };
    let mut buffer = [0_u8; 64];
    while let Ok(read) = pipe.read(&mut buffer) {
        if read == 0 {
            break;
        }
    }
    std::process::exit(0);
}

/// Starts the impostor, unconfined, in a job of its own that the returned value kills.
fn spawn_impostor(pipe: &RelayPipeName) -> HostProcess {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(helper_arguments("impostor_helper", None))
        .env(IMPOSTOR, pipe.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    HostProcess::spawn(
        &mut command,
        ProcessRole::GuestRelay {
            execution: sandbox(),
        },
    )
    .unwrap()
}

/// Whether an AppContainer profile of `name` exists: creating it again reports it. One
/// created by this check is deleted at once.
fn profile_exists(name: &str) -> bool {
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut sid: PSID = null_mut();
    let result = unsafe {
        CreateAppContainerProfile(
            wide.as_ptr(),
            wide.as_ptr(),
            wide.as_ptr(),
            null(),
            0,
            &mut sid,
        )
    };
    if result >= 0 {
        unsafe {
            FreeSid(sid);
            assert!(DeleteAppContainerProfile(wide.as_ptr()) >= 0);
        }
        return false;
    }
    let code = u32::from_ne_bytes(result.to_ne_bytes());
    assert!(
        code == 0x8007_00B7 || code == 183,
        "unexpected HRESULT {code:#x}"
    );
    true
}

/// The ACEs of `acl`, each as its header type, flags, mask and SID bytes.
fn aces(acl: *const ACL) -> Vec<(u8, u8, u32, Vec<u8>)> {
    let mut size = ACL_SIZE_INFORMATION::default();
    assert_ne!(
        unsafe {
            GetAclInformation(
                acl,
                (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
                u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>()).unwrap(),
                AclSizeInformation,
            )
        },
        0
    );
    (0..size.AceCount)
        .map(|index| {
            let mut ace = null_mut();
            assert_ne!(unsafe { GetAce(acl, index, &mut ace) }, 0);
            // ACCESS_ALLOWED_ACE and SYSTEM_MANDATORY_LABEL_ACE share this layout.
            let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
            unsafe {
                let header = (*allowed).Header;
                let sid: PSID = std::ptr::addr_of!((*allowed).SidStart).cast_mut().cast();
                let length =
                    usize::try_from(windows_sys::Win32::Security::GetLengthSid(sid)).unwrap();
                let bytes = std::slice::from_raw_parts(sid.cast::<u8>(), length).to_vec();
                (header.AceType, header.AceFlags, (*allowed).Mask, bytes)
            }
        })
        .collect()
}

/// Whether the executable's DACL holds an ACE for `sid`.
fn executable_grants(sid: &[u8]) -> bool {
    let path: Vec<u16> = std::env::current_exe()
        .unwrap()
        .as_os_str()
        .encode_wide_vec();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    let read = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(read, ERROR_SUCCESS);
    let found = aces(dacl).iter().any(|(_, _, _, ace_sid)| ace_sid == sid);
    unsafe { LocalFree(descriptor) };
    found
}

trait EncodeWide {
    fn encode_wide_vec(&self) -> Vec<u16>;
}

impl EncodeWide for std::ffi::OsStr {
    fn encode_wide_vec(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(Some(0)).collect()
    }
}

/// A file in the user's profile that this test process can open.
fn readable_profile_file() -> std::path::PathBuf {
    let profile = std::env::var_os("USERPROFILE").expect("USERPROFILE is set");
    std::fs::read_dir(&profile)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_file() && std::fs::File::open(path).is_ok())
        .expect("a readable file in the user's profile")
}

/// Ends `launched`, checks the host saw it end, and that its grant and profile are gone.
fn end_and_check_cleanup(
    launched: LaunchedRelay,
    escalation: Escalation,
) -> crate::foundation::process::TerminationProof {
    let sid = launched.container_sid().to_vec();
    let name = launched.profile_name().to_owned();
    assert!(
        executable_grants(&sid),
        "the executable is granted while the relay runs"
    );
    assert!(
        profile_exists(&name),
        "the profile exists while the relay runs"
    );
    let end = launched.end(escalation);
    end.cleanup.unwrap();
    assert!(!executable_grants(&sid), "the grant is revoked");
    assert!(!profile_exists(&name), "the profile is deleted");
    end.proof.unwrap()
}

/// The broker's side of the one exchange the relay helper forwards.
fn answer_one_exchange(link: &mut LinkPipe<BrokerSide>) {
    match link.receive(PATIENT).unwrap() {
        RelayMessage::Forward {
            exchange,
            route,
            request,
        } => {
            assert_eq!(exchange, ExchangeId::FIRST);
            assert_eq!(route, RouteId::new(ROUTE).unwrap());
            assert_eq!(request.as_slice(), FORWARDED);
        }
        other => panic!("expected a forward, got {other:?}"),
    }
    link.send(
        BrokerMessage::Response {
            exchange: ExchangeId::FIRST,
            status: 200,
            response: WireBytes::new(RESPONSE.to_vec()),
        },
        PATIENT,
    )
    .unwrap();
    assert_eq!(
        link.receive(PATIENT).unwrap(),
        RelayMessage::Close {
            reason: CloseReason::Finished
        }
    );
}

#[test]
#[ignore = "creates and removes an AppContainer profile and an ACL grant in the user's profile; run with --ignored"]
fn a_launched_relay_runs_in_an_appcontainer_at_low_integrity_with_no_capabilities_and_inherits_no_handle(
) {
    // An inheritable handle of this process, which a start without a handle list would
    // pass on.
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let event = unsafe { OwnedHandle::from_raw_handle(CreateEventW(&attributes, 1, 0, null())) };
    let launched = launch(&sandbox(), "confined_helper_sleep", None);
    let process = unsafe {
        OwnedHandle::from_raw_handle(OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE,
            0,
            launched.identity().pid,
        ))
    };
    let facts = process_token_facts(process.as_handle()).unwrap();
    assert!(facts.app_container);
    assert_eq!(facts.integrity_rid, LOW_INTEGRITY_RID);
    assert_eq!(facts.capabilities, 0);
    assert_eq!(
        facts.container_sid.as_deref(),
        Some(launched.container_sid())
    );
    // Whatever the relay holds at the event's handle value, it is not the event.
    let mut duplicate = null_mut();
    let duplicated = unsafe {
        DuplicateHandle(
            process.as_raw_handle(),
            event.as_raw_handle(),
            GetCurrentProcess(),
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if duplicated != 0 {
        let duplicate = unsafe { OwnedHandle::from_raw_handle(duplicate) };
        assert_eq!(
            unsafe { CompareObjectHandles(event.as_raw_handle(), duplicate.as_raw_handle()) },
            0
        );
    }
    let proof = end_and_check_cleanup(launched, END_ESCALATION);
    assert!(matches!(proof.ending(), Ending::Killed { .. }));
}

#[test]
#[ignore = "creates and removes an AppContainer profile and an ACL grant in the user's profile; run with --ignored"]
fn a_launched_relay_cannot_open_a_file_in_the_users_profile() {
    let file = readable_profile_file();
    let launched = launch(
        &sandbox(),
        "confined_helper_open_file",
        Some(file.to_str().unwrap()),
    );
    let proof = launched.process().wait_ended(PATIENT).unwrap();
    assert_eq!(
        proof.exit_code(),
        0,
        "the confined helper opened {file:?} or failed otherwise"
    );
    end_and_check_cleanup(launched, END_ESCALATION);
}

#[test]
#[ignore = "creates and removes an AppContainer profile and an ACL grant in the user's profile; run with --ignored"]
fn a_launched_relay_cannot_read_the_brokers_process_so_admits_it_by_pid() {
    let launched = launch(
        &sandbox(),
        "confined_helper_open_broker",
        Some(&std::process::id().to_string()),
    );
    let proof = launched.process().wait_ended(PATIENT).unwrap();
    assert_eq!(
        proof.exit_code(),
        0,
        "the confined helper read this process's identity"
    );
    end_and_check_cleanup(launched, END_ESCALATION);
}

#[test]
#[ignore = "creates and removes an AppContainer profile and an ACL grant in the user's profile; run with --ignored"]
fn an_unconfined_impostor_is_refused_and_the_launched_relay_is_admitted_by_identity() {
    let mut launched = launch(&sandbox(), "confined_helper_late_relay", None);
    let impostor = spawn_impostor(launched.pipe_name());
    match launched.accept(PATIENT) {
        Err(PipeError::Peer(PeerRefusal::OtherProcess { pid })) => {
            assert_eq!(pid, impostor.identity().pid);
        }
        other => panic!("the impostor was not refused: {other:?}"),
    }
    assert_eq!(impostor.wait_ended(PATIENT).unwrap().exit_code(), 0);
    let mut link = launched.accept(PATIENT).unwrap();
    assert_eq!(link.peer(), launched.identity());
    answer_one_exchange(&mut link);
    assert_eq!(
        launched.process().wait_ended(PATIENT).unwrap().exit_code(),
        0
    );
    end_and_check_cleanup(launched, END_ESCALATION);
}

#[test]
#[ignore = "creates and removes an AppContainer profile and an ACL grant in the user's profile; run with --ignored"]
fn one_exchange_crosses_the_link_from_a_launched_relay_end_to_end() {
    let mut launched = launch(&sandbox(), "confined_helper_relay", None);
    let mut link = launched.accept(PATIENT).unwrap();
    assert_eq!(link.peer(), launched.identity());
    answer_one_exchange(&mut link);
    let proof = launched.process().wait_ended(PATIENT).unwrap();
    assert_eq!(proof.exit_code(), 0, "the relay or its guest failed");
    assert_eq!(proof.ending(), Ending::Exited);
    let proof = end_and_check_cleanup(launched, END_ESCALATION);
    assert_eq!(proof.exit_code(), 0);
}

#[test]
#[ignore = "creates and removes an AppContainer profile and an ACL grant in the user's profile; run with --ignored"]
fn killing_the_job_ends_a_relay_mid_exchange_and_removes_its_profile_and_grant() {
    let mut launched = launch(&sandbox(), "confined_helper_relay", None);
    let mut link = launched.accept(PATIENT).unwrap();
    assert!(matches!(
        link.receive(PATIENT).unwrap(),
        RelayMessage::Forward { .. }
    ));
    let proof = end_and_check_cleanup(
        launched,
        Escalation {
            grace: Duration::ZERO,
            kill_wait: PATIENT,
        },
    );
    assert!(matches!(proof.ending(), Ending::Killed { .. }));
    assert_eq!(proof.exit_code(), KILLED_EXIT_CODE);
    assert!(matches!(
        link.receive(PATIENT),
        Err(PipeError::Disconnected)
    ));
}

#[test]
fn the_container_pipe_grants_the_appcontainer_read_and_write_only_under_a_low_label() {
    // A real AppContainer SID, from a profile of this test's own, deleted after.
    let name = format!(
        "yougori.relay.test.{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut sid: PSID = null_mut();
    assert!(
        unsafe {
            CreateAppContainerProfile(
                wide.as_ptr(),
                wide.as_ptr(),
                wide.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        } >= 0
    );
    let container = unsafe {
        let length = usize::try_from(windows_sys::Win32::Security::GetLengthSid(sid)).unwrap();
        let bytes = std::slice::from_raw_parts(sid.cast::<u8>(), length).to_vec();
        FreeSid(sid);
        bytes
    };
    struct DeleteProfile(Vec<u16>);
    impl Drop for DeleteProfile {
        fn drop(&mut self) {
            unsafe { DeleteAppContainerProfile(self.0.as_ptr()) };
        }
    }
    let _profile = DeleteProfile(wide);
    let pipe = RelayPipeName::new(format!(
        r"\\.\pipe\yougori-relay-process-test-{}",
        uuid::Uuid::new_v4().simple()
    ))
    .unwrap();
    // A SID that is not an AppContainer's, such as Everyone (S-1-1-0), is refused.
    let everyone = [1_u8, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    assert!(matches!(
        RelayPipeListener::create_for_container(pipe.clone(), &everyone),
        Err(PipeError::HostCall { os_error: 1337, .. })
    ));
    let listener = RelayPipeListener::create_for_container(pipe.clone(), &container).unwrap();
    let path: Vec<u16> = pipe.as_str().encode_utf16().chain(Some(0)).collect();
    let client = unsafe {
        OwnedHandle::from_raw_handle(CreateFileW(
            path.as_ptr(),
            READ_CONTROL,
            0,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        ))
    };
    let (mut dacl, mut sacl, mut descriptor) = (null_mut(), null_mut(), null_mut());
    let read = unsafe {
        GetSecurityInfo(
            client.as_raw_handle(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            &mut sacl,
            &mut descriptor,
        )
    };
    assert_eq!(read, ERROR_SUCCESS);
    let granted = aces(dacl);
    assert_eq!(
        granted.len(),
        2,
        "the user and the AppContainer, no one else"
    );
    let container_aces: Vec<_> = granted
        .iter()
        .filter(|(_, _, _, ace_sid)| *ace_sid == container)
        .collect();
    assert_eq!(container_aces.len(), 1);
    assert_eq!(container_aces[0].0, 0, "an access-allowed ACE");
    assert_eq!(container_aces[0].2, CONTAINER_PIPE_ACCESS);
    let label = aces(sacl);
    assert_eq!(label.len(), 1);
    // SYSTEM_MANDATORY_LABEL_ACE_TYPE (0x11), no write up (0x1), Low (S-1-16-4096).
    assert_eq!(label[0].0, 0x11);
    assert_eq!(label[0].2, 0x1);
    let low = [1_u8, 1, 0, 0, 0, 0, 0, 16, 0, 0x10, 0, 0];
    assert_eq!(label[0].3, low);
    unsafe { LocalFree(descriptor) };
    drop(client);
    drop(listener);
}

/// Reports what the confined helper's environment holds, as its exit code: bit 0 `PATH`,
/// 1 `TEMP`, 2 `TMP`, 3 `USERPROFILE`, 4 `APPDATA`, 5 `SystemRoot`, 6 any variable holding
/// the user's profile path (its argument), 7 `LOCALAPPDATA`, and the count of variables
/// from bit 8.
#[test]
fn confined_helper_environment() {
    if check_confined().is_err() {
        return;
    }
    let profile = helper_argument().unwrap_or_default().to_ascii_lowercase();
    let has = |name: &str| std::env::var_os(name).is_some();
    let holds_profile = !profile.is_empty()
        && std::env::vars_os().any(|(_, value)| {
            value
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains(&profile)
        });
    let mut code = 0_i32;
    for (bit, present) in [
        has("PATH"),
        has("TEMP"),
        has("TMP"),
        has("USERPROFILE"),
        has("APPDATA"),
        has("SystemRoot"),
        holds_profile,
        has("LOCALAPPDATA"),
    ]
    .into_iter()
    .enumerate()
    {
        if present {
            code |= 1 << bit;
        }
    }
    let count = i32::try_from(std::env::vars_os().count())
        .unwrap_or(255)
        .min(255);
    std::process::exit(code | (count << 8));
}

/// The variable that makes this executable a sleeping, unconfined child of the spawner in
/// [`no_concurrent_std_spawn_holds_a_handle_of_the_relays_link`].
const SLEEPER: &str = "YG_RELAY_PROCESS_SLEEPER";

#[test]
fn sleeper_helper() {
    if std::env::var_os(SLEEPER).is_some() {
        thread::sleep(Duration::from_secs(120));
        std::process::exit(0);
    }
}

/// Children started with `std::process::Command::spawn`, which inherits every inheritable
/// handle of this process, killed when dropped.
struct Spawned(Vec<std::process::Child>);

impl Drop for Spawned {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
#[ignore = "creates and removes an AppContainer profile and an ACL grant in the user's profile; run with --ignored"]
fn no_concurrent_std_spawn_holds_a_handle_of_the_relays_link() {
    // A thread starts sleeping children the ordinary way, with handle inheritance, all
    // through the launch and the admission of the relay.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let spawner = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let mut spawned = Spawned(Vec::new());
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                let child = Command::new(std::env::current_exe().unwrap())
                    .args(helper_arguments("sleeper_helper", None))
                    .env(SLEEPER, "1")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                spawned.0.push(child);
                thread::sleep(Duration::from_millis(2));
            }
            spawned
        })
    };
    let mut launched = launch(&sandbox(), "confined_helper_relay", None);
    let mut link = launched.accept(PATIENT).unwrap();
    assert!(matches!(
        link.receive(PATIENT).unwrap(),
        RelayMessage::Forward { .. }
    ));
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut spawned = spawner.join().unwrap();
    assert!(spawned.0.len() >= 3, "the spawner ran during the launch");
    // The broker drops its end of the link. Had any of those children inherited a handle
    // of it, the relay would never see the end; it sees it and ends on its own.
    drop(link);
    let proof = launched.process().wait_ended(PATIENT).unwrap();
    assert_eq!(proof.ending(), Ending::Exited);
    assert_eq!(proof.exit_code(), 2, "the relay ends on the link's failure");
    assert!(
        spawned
            .0
            .iter_mut()
            .all(|child| child.try_wait().unwrap().is_none()),
        "the children still run"
    );
    end_and_check_cleanup(launched, END_ESCALATION);
}

/// A listener of this process for a "relay" that is this process too, with the binding
/// and key both ends use. (A launched relay's pipe is named after its identity,
/// [`RelayPipeName::for_relay`].)
fn own_listener() -> (RelayPipeListener, LinkBinding, Vec<u8>) {
    let me = ProcessIdentity::holder_of(std::process::id())
        .unwrap()
        .unwrap();
    let binding = LinkBinding {
        sandbox: sandbox(),
        relay: me,
        session: LinkSessionId::generate(),
    };
    // A name of its own, so tests that run at once do not meet.
    let name = RelayPipeName::new(format!(
        r"\\.\pipe\yougori-relay-process-own-{}",
        uuid::Uuid::new_v4().simple()
    ))
    .unwrap();
    let listener = RelayPipeListener::create(name).unwrap();
    (listener, binding, vec![9_u8; 32])
}

#[test]
fn a_handoff_reaches_the_admitted_relay_ahead_of_its_link() {
    let (mut listener, binding, key) = own_listener();
    let name = listener.name().clone();
    let me = binding.relay;
    let handoff = b"{\"handoff\":true}".to_vec();
    let (server_binding, server_key, sent) = (binding.clone(), key.clone(), handoff.clone());
    let server = thread::spawn(move || {
        let mut link = listener
            .accept_with_handoff(
                server_binding,
                LinkKey::new(server_key).unwrap(),
                &sent,
                PATIENT,
            )
            .unwrap();
        link.receive(PATIENT).unwrap()
    });
    let mut handover = open_confined_relay(&name, std::process::id(), PATIENT).unwrap();
    assert_eq!(handover.server(), std::process::id());
    assert_eq!(handover.read_handoff(64, PATIENT).unwrap(), handoff);
    let mut link = handover
        .into_link(binding, LinkKey::new(key).unwrap(), &me)
        .unwrap();
    link.send(
        RelayMessage::Close {
            reason: CloseReason::Finished,
        },
        PATIENT,
    )
    .unwrap();
    assert_eq!(
        server.join().unwrap(),
        RelayMessage::Close {
            reason: CloseReason::Finished
        }
    );
}

#[test]
fn a_handoff_over_the_relays_bound_is_refused_before_its_bytes_are_read() {
    let (mut listener, binding, key) = own_listener();
    let name = listener.name().clone();
    let server = thread::spawn(move || {
        listener
            .accept_with_handoff(binding, LinkKey::new(key).unwrap(), &[b'x'; 64], PATIENT)
            .map(|_| ())
    });
    let mut handover = open_confined_relay(&name, std::process::id(), PATIENT).unwrap();
    assert_eq!(
        handover.read_handoff(16, PATIENT).unwrap_err(),
        PipeError::Link(LinkRefusal::Oversize {
            declared: 64,
            max: 16
        })
    );
    drop(handover);
    let _ = server.join().unwrap();
}

#[test]
fn a_confined_relay_refuses_a_pipe_server_that_is_not_its_creator() {
    let (mut listener, binding, key) = own_listener();
    let name = listener.name().clone();
    let server = thread::spawn(move || {
        let _ = listener.accept_with_handoff(binding, LinkKey::new(key).unwrap(), b"x", PATIENT);
    });
    let other = std::process::id().wrapping_add(4);
    assert_eq!(
        open_confined_relay(&name, other, PATIENT).unwrap_err(),
        PipeError::Peer(PeerRefusal::OtherProcess {
            pid: std::process::id()
        })
    );
    let _ = server.join();
}

#[test]
#[ignore = "creates and removes an AppContainer profile and an ACL grant in the user's profile; run with --ignored"]
fn a_launched_relays_environment_holds_nothing_of_the_brokers_and_no_host_path() {
    let profile = std::env::var("USERPROFILE").unwrap();
    let launched = launch(&sandbox(), "confined_helper_environment", Some(&profile));
    let code = launched.process().wait_ended(PATIENT).unwrap().exit_code();
    let has = |bit: u32| code & (1 << bit) != 0;
    assert!(
        !has(0) && !has(3) && !has(4),
        "no PATH, USERPROFILE or APPDATA: {code:#x}"
    );
    assert!(
        !has(6),
        "no variable holds the user's profile path: {code:#x}"
    );
    assert!(
        has(5) && has(7),
        "SystemRoot and the LOCALAPPDATA placeholder: {code:#x}"
    );
    // Windows adds TEMP and TMP for an AppContainer start, from LOCALAPPDATA.
    assert!(code >> 8 <= 4, "at most four variables: {code:#x}");
    end_and_check_cleanup(launched, END_ESCALATION);
}
