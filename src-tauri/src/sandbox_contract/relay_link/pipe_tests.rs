//! Tests of the named-pipe adapter. Every pipe has a unique name and is closed by its test.
//! The only process started is this test executable again, running [`relay_helper`] as
//! the relay, the way PX1's tests start theirs; it connects, exchanges three frames and
//! exits. No network is touched.

use std::process::{Child, Command, Stdio};
use std::ptr::{addr_of, null, null_mut};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows_sys::Wdk::Storage::FileSystem::{
    FilePipeLocalInformation, NtQueryInformationFile, FILE_PIPE_LOCAL_INFORMATION,
    FILE_PIPE_REJECT_REMOTE_CLIENTS, FILE_PIPE_SERVER_END,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetKernelObjectSecurity,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::pipe::judge_peer;
use super::pipe_os::{owned, UserSid};
use super::*;
use crate::foundation::ids::ExecutionId;
use crate::foundation::process::{IdentityCheck, ProcessError, ProcessIdentity};
use crate::sandbox_contract::destinations::RouteId;

/// The environment variable that makes the test executable the relay helper, holding its
/// [`HelperSpec`] as JSON.
const HELPER: &str = "YG_RELAY_LINK_HELPER";

/// How long a helper may take to start and answer: a whole test executable starts.
const PATIENT: Duration = Duration::from_secs(20);

const SHORT: Duration = Duration::from_millis(200);

const REQUEST: &[u8] = b"GET /v1/models HTTP/1.1\r\nhost: api.example.com\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";

/// What the helper needs: in production the launch hands these over (outside the module).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperSpec {
    pipe: String,
    key: String,
    sandbox: ExecutionId,
    session: LinkSessionId,
    broker: ProcessIdentity,
}

/// The relay helper: an ordinary run, without the variable, does nothing. With it, the
/// helper connects as the relay, forwards one request, checks the broker's response,
/// closes and exits with 0; any other code names the step that failed.
#[test]
fn relay_helper() {
    let Ok(text) = std::env::var(HELPER) else {
        return;
    };
    std::process::exit(match run_relay(&text) {
        Ok(()) => 0,
        Err(code) => code,
    });
}

fn run_relay(text: &str) -> Result<(), i32> {
    let spec: HelperSpec = serde_json::from_str(text).map_err(|_| 10)?;
    let me = ProcessIdentity::holder_of(std::process::id())
        .ok()
        .flatten()
        .ok_or(11)?;
    let name = RelayPipeName::new(spec.pipe).map_err(|_| 12)?;
    let key = LinkKey::new(hex::decode(spec.key).map_err(|_| 13)?).map_err(|_| 13)?;
    let binding = LinkBinding {
        sandbox: spec.sandbox,
        relay: me,
        session: spec.session,
    };
    let mut link = connect_relay(&name, binding, key, &spec.broker, PATIENT).map_err(|_| 14)?;
    link.send(forward(0), PATIENT).map_err(|_| 15)?;
    match link.receive(PATIENT) {
        Ok(BrokerMessage::Response {
            exchange,
            status: 200,
            response,
        }) if exchange == ExchangeId::FIRST && response.as_slice() == RESPONSE => {}
        _ => return Err(16),
    }
    link.send(
        RelayMessage::Close {
            reason: CloseReason::Finished,
        },
        PATIENT,
    )
    .map_err(|_| 17)?;
    Ok(())
}

/// A helper process, killed if the test ends first.
struct Helper(Child);

impl Helper {
    fn spawn(spec: &HelperSpec) -> Self {
        let path = module_path!();
        let tests = path.split_once("::").map_or(path, |(_, rest)| rest);
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("{tests}::relay_helper"),
                "--test-threads=1",
                "--quiet",
            ])
            .env(HELPER, serde_json::to_string(spec).unwrap())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self(child)
    }

    /// The helper's identity, read while this test holds its handle, so the PID cannot
    /// name another process meanwhile.
    fn identity(&self) -> ProcessIdentity {
        ProcessIdentity::holder_of(self.0.id()).unwrap().unwrap()
    }

    fn exit_code(&mut self) -> i32 {
        let deadline = Instant::now() + PATIENT;
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status.code().unwrap();
            }
            assert!(Instant::now() < deadline, "the helper did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn key_bytes() -> Vec<u8> {
    (0_u8..32).map(|byte| byte.wrapping_mul(7)).collect()
}

fn key() -> LinkKey {
    LinkKey::new(key_bytes()).unwrap()
}

fn sandbox() -> ExecutionId {
    ExecutionId::new("exe-relay-link-pipe").unwrap()
}

fn binding(relay: ProcessIdentity, session: LinkSessionId) -> LinkBinding {
    LinkBinding {
        sandbox: sandbox(),
        relay,
        session,
    }
}

fn this_process() -> ProcessIdentity {
    ProcessIdentity::holder_of(std::process::id())
        .unwrap()
        .unwrap()
}

fn forward(exchange: u64) -> RelayMessage {
    RelayMessage::Forward {
        exchange: ExchangeId::new(exchange),
        route: RouteId::new("provider-api").unwrap(),
        request: WireBytes::new(REQUEST.to_vec()),
    }
}

/// A fresh link session and its pipe.
fn fresh() -> (LinkSessionId, RelayPipeName, RelayPipeListener) {
    let session = LinkSessionId::generate();
    let name = RelayPipeName::for_session(&session);
    let listener = RelayPipeListener::create(name.clone()).unwrap();
    (session, name, listener)
}

#[test]
fn the_registered_relay_process_is_admitted_after_another_client_is_refused() {
    let (session, name, mut listener) = fresh();
    let broker = this_process();
    // A client of this process takes the pipe's instance before the relay starts.
    let squatter = connect_relay(&name, binding(broker, session), key(), &broker, PATIENT).unwrap();
    let mut helper = Helper::spawn(&HelperSpec {
        pipe: name.as_str().to_owned(),
        key: hex::encode(key_bytes()),
        sandbox: sandbox(),
        session,
        broker,
    });
    let relay = helper.identity();
    assert_eq!(
        listener
            .accept(binding(relay, session), key(), PATIENT)
            .unwrap_err(),
        PipeError::Peer(PeerRefusal::OtherProcess { pid: broker.pid })
    );
    drop(squatter);

    // The relay, waiting while the instance was taken, gets it now and is admitted.
    let mut link = listener
        .accept(binding(relay, session), key(), PATIENT)
        .unwrap();
    assert_eq!(link.peer(), relay);
    assert_eq!(link.receive(PATIENT).unwrap(), forward(0));
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
    assert_eq!(
        link.session().state(),
        &LinkState::Closed {
            by: LinkDirection::RelayToBroker,
            reason: CloseReason::Finished
        }
    );
    assert_eq!(helper.exit_code(), 0);
    assert_eq!(
        link.receive(SHORT).unwrap_err(),
        PipeError::Link(LinkRefusal::Closed)
    );
    // The one instance went to the link.
    assert_eq!(
        listener
            .accept(binding(relay, session), key(), SHORT)
            .unwrap_err(),
        PipeError::Spent
    );
}

#[test]
fn this_process_under_a_wrong_identity_is_refused_before_any_frame_is_read() {
    let me = this_process();
    // The same PID with another creation time: a reused PID is never the relay.
    let reused = ProcessIdentity {
        start_time_ticks: me.start_time_ticks + 1,
        ..me
    };
    let elsewhere = ProcessIdentity {
        pid: me.pid.wrapping_add(4),
        ..me
    };
    let cases = [
        (reused, PeerRefusal::PidReused { registered: reused }),
        (elsewhere, PeerRefusal::OtherProcess { pid: me.pid }),
    ];
    for (registered, refusal) in cases {
        let (session, name, mut listener) = fresh();
        let mut client = connect_relay(&name, binding(me, session), key(), &me, PATIENT).unwrap();
        // A well-formed frame waits in the pipe; the refusal comes before it is read.
        client.send(forward(0), PATIENT).unwrap();
        assert_eq!(
            listener
                .accept(binding(registered, session), key(), PATIENT)
                .unwrap_err(),
            PipeError::Peer(refusal)
        );
        assert_eq!(client.receive(SHORT).unwrap_err(), PipeError::Disconnected);
        assert_eq!(
            client.session().state(),
            &LinkState::Failed(LinkRefusal::Interrupted)
        );
        // The listener keeps its instance for the registered relay.
        assert!(listener.raw_pipe().is_some());
    }
}

#[test]
fn a_relay_refuses_a_server_that_is_not_the_broker() {
    let (session, name, _listener) = fresh();
    let me = this_process();
    let not_the_broker = ProcessIdentity {
        start_time_ticks: me.start_time_ticks + 1,
        ..me
    };
    assert_eq!(
        connect_relay(&name, binding(me, session), key(), &not_the_broker, PATIENT).unwrap_err(),
        PipeError::Peer(PeerRefusal::PidReused {
            registered: not_the_broker
        })
    );
}

/// The pipe's local information as the named-pipe file system reports it.
fn local_information(pipe: HANDLE) -> FILE_PIPE_LOCAL_INFORMATION {
    let mut status = IO_STATUS_BLOCK::default();
    let mut information = FILE_PIPE_LOCAL_INFORMATION::default();
    let size = u32::try_from(std::mem::size_of::<FILE_PIPE_LOCAL_INFORMATION>()).unwrap();
    // SAFETY: the handle is open and both structures are live and of the stated size.
    let read = unsafe {
        NtQueryInformationFile(
            pipe,
            &mut status,
            (&mut information as *mut FILE_PIPE_LOCAL_INFORMATION).cast(),
            size,
            FilePipeLocalInformation,
        )
    };
    assert_eq!(read, 0, "NTSTATUS {read:#x}");
    information
}

/// The pipe's DACL: whether it is protected, and its one ACE's SID and type.
fn assert_owner_only(pipe: HANDLE) {
    let mut needed = 0_u32;
    // SAFETY: a null buffer of length zero asks only for the length needed.
    unsafe { GetKernelObjectSecurity(pipe, DACL_SECURITY_INFORMATION, null_mut(), 0, &mut needed) };
    assert!(needed > 0);
    let mut buffer = vec![0_u64; usize::try_from(needed).unwrap().div_ceil(8)];
    let length = u32::try_from(buffer.len() * 8).unwrap();
    let descriptor = buffer.as_mut_ptr().cast();
    // SAFETY: `buffer` holds `length` writable bytes, aligned for a descriptor.
    let read = unsafe {
        GetKernelObjectSecurity(
            pipe,
            DACL_SECURITY_INFORMATION,
            descriptor,
            length,
            &mut needed,
        )
    };
    assert_ne!(read, 0);
    let (mut control, mut revision) = (0_u16, 0_u32);
    // SAFETY: `descriptor` is the self-relative descriptor just read.
    assert_ne!(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
        0
    );
    assert_ne!(control & SE_DACL_PROTECTED, 0, "the DACL is not protected");
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: as above; the out pointers are live.
    assert_ne!(
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) },
        0
    );
    assert!(present != 0 && !dacl.is_null());
    let mut sizes = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` points into `buffer`; `sizes` is live and of the stated size.
    assert_ne!(
        unsafe {
            GetAclInformation(
                dacl,
                (&mut sizes as *mut ACL_SIZE_INFORMATION).cast(),
                u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>()).unwrap(),
                AclSizeInformation,
            )
        },
        0
    );
    assert_eq!(sizes.AceCount, 1, "exactly one entry: the current user");
    let mut ace = null_mut();
    // SAFETY: index 0 exists; `ace` is live.
    assert_ne!(unsafe { GetAce(dacl, 0, &mut ace) }, 0);
    let ace: *const ACCESS_ALLOWED_ACE = ace.cast();
    // SAFETY: the one ACE is an ACE inside `buffer`; its header says which kind.
    let kind = unsafe { (*ace).Header.AceType };
    assert_eq!(kind, 0, "an access-allowed entry");
    let user = UserSid::current().unwrap();
    // SAFETY: both SIDs are valid: the ACE's inside `buffer`, the user's inside `user`.
    let same = unsafe { EqualSid(addr_of!((*ace).SidStart).cast_mut().cast(), user.sid()) };
    assert_ne!(same, 0, "the entry is not the current user");
}

#[test]
fn the_pipe_rejects_remote_clients_and_grants_only_the_current_user() {
    assert_ne!(RELAY_PIPE_MODE & PIPE_REJECT_REMOTE_CLIENTS, 0);
    let (_session, _name, listener) = fresh();
    let pipe = listener.raw_pipe().unwrap();
    let information = local_information(pipe);
    assert_ne!(
        information.NamedPipeType & FILE_PIPE_REJECT_REMOTE_CLIENTS,
        0,
        "the pipe accepts remote clients"
    );
    assert_eq!(information.MaximumInstances, 1);
    assert_eq!(information.NamedPipeEnd, FILE_PIPE_SERVER_END);
    assert_owner_only(pipe);
    // A name on another computer is never a link pipe.
    for name in [
        r"\\server\pipe\yougori-relay-link",
        r"\\.\pipe\",
        r"\\.\pipe\a\b",
        r"\\?\pipe\x",
        "yougori-relay-link",
    ] {
        assert_eq!(
            RelayPipeName::new(name),
            Err(PipeError::InvalidName),
            "{name}"
        );
    }
    assert!(RelayPipeName::new(r"\\.\pipe\yougori-relay-link.1_a").is_ok());
}

#[test]
fn a_name_has_one_instance_created_first_and_every_wait_is_bounded() {
    let (session, name, mut listener) = fresh();
    // The one instance exists, so no second one is made.
    assert_eq!(
        RelayPipeListener::create(name.clone()).unwrap_err(),
        PipeError::HostCall {
            call: PipeCall::CreatePipe,
            os_error: ERROR_PIPE_BUSY
        }
    );
    // A pipe someone else created first under a name is never taken over.
    let squatted = RelayPipeName::for_session(&LinkSessionId::generate());
    let wide: Vec<u16> = squatted.as_str().encode_utf16().chain(Some(0)).collect();
    // SAFETY: `wide` is a NUL-terminated name; default security; the handle is closed
    // below.
    let raw = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            RELAY_PIPE_MODE,
            PIPE_UNLIMITED_INSTANCES,
            0,
            0,
            0,
            null(),
        )
    };
    assert_ne!(raw, INVALID_HANDLE_VALUE);
    let squatter = owned(raw).unwrap();
    assert_eq!(
        RelayPipeListener::create(squatted).unwrap_err(),
        PipeError::HostCall {
            call: PipeCall::CreatePipe,
            os_error: ERROR_ACCESS_DENIED
        }
    );
    drop(squatter);
    let started = Instant::now();
    assert_eq!(
        listener
            .accept(binding(this_process(), session), key(), SHORT)
            .unwrap_err(),
        PipeError::TimedOut
    );
    assert!(started.elapsed() < PATIENT);
    assert_eq!(listener.name(), &name);
}

#[test]
fn a_peer_is_admitted_only_as_the_same_process() {
    let registered = ProcessIdentity {
        pid: 4242,
        start_time_ticks: 133_000_000_000_000_000,
    };
    let check = |found: IdentityCheck| move |_: &ProcessIdentity| Ok(found);
    assert_eq!(
        judge_peer(&registered, 4242, check(IdentityCheck::Same)),
        Ok(())
    );
    assert_eq!(
        judge_peer(&registered, 4243, check(IdentityCheck::Same)),
        Err(PipeError::Peer(PeerRefusal::OtherProcess { pid: 4243 }))
    );
    assert_eq!(
        judge_peer(&registered, 4242, check(IdentityCheck::Reused)),
        Err(PipeError::Peer(PeerRefusal::PidReused { registered }))
    );
    assert_eq!(
        judge_peer(&registered, 4242, check(IdentityCheck::Gone)),
        Err(PipeError::Peer(PeerRefusal::Gone { registered }))
    );
    let unidentified = ProcessError::HostCall {
        call: crate::foundation::process::HostCall::OpenProcess,
        os_error: 5,
    };
    assert_eq!(
        judge_peer(&registered, 4242, |_| Err(unidentified.clone())),
        Err(PipeError::Identity(unidentified.clone()))
    );
}
