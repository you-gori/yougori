//! Tests for the control session's transport (M16G; VM-W39 "loss of control connection";
//! VM-W41 "remote reconnect cannot revive expired authority", "host-key changes
//! rejected"; VM part §6.3, §4.5), with this test executable as the OpenSSH client and the
//! remote control agent behind it (see `fake_remote`). A real V12 adapter runs on V12's
//! fakes and a real CORE-04 coordinator, as in the management tests. Nothing here runs
//! `ssh` or opens a socket.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::control_channel::{ControlEndReason, CONTROL_KEY_BYTES, MAX_CONTROL_FRAME_BYTES};
use super::control_transport::{
    ControlAgent, ControlEnd, ControlInvocation, ControlLimits, ControlLimitsRefusal,
    ControlTransport, ControlTransportRefusal, CONTROL_BINDING_DOMAIN, MAX_CONTROL_SILENCE,
};
use super::fake_client::Record;
use super::fake_remote::{
    ControlScript, Fault, CONTROL_LOG_FILE, CONTROL_RECORD_FILE, CONTROL_RUNS_FILE,
    CONTROL_SCRIPT_FILE,
};
use super::fakes::{
    authority, ed25519_blob, host_id, identity_for, mgmt_key, Scratch, PUBLISHED_ED25519_SHA256,
};
use super::invocation::{IdentityFile, SshLimits};
use super::known_hosts::{EnrolledHostKey, KnownHostsFile, SshTarget};
use super::management::RejectedHostKey;
use super::outcome::{HostKeyEvidence, OutputStream, SshOutcome, SshTermination, TimeoutPhase};
use super::process::CLIENT_ENVIRONMENT;
use super::protection::protect_identity_file;
use crate::foundation::ids::{DigestBuilder, ExecutionCategory, ManualClock, OperationId};
use crate::sandbox_contract::provider::{find_encoded, SharedSpendLedger, SpendLedger};
use crate::sandbox_contract::remote::fakes::{
    account, attempt, config, container_offering, control_key, dedicated_offering,
    explicit_container, parent, pod_execution, provision_effect, session_id, session_key,
    vm_request, FakeProvider, GrantAll, HostWorld, HOUR, MINUTE, SECOND,
};
use crate::sandbox_contract::remote::{
    AdapterRefusal, AdapterState, AdapterStep, AuthorityEnd, ControlBody, ControlFrame, ControlKey,
    ControlRefusal, ControlSession, CoordinatorDelegation, Delegation, EnrollmentEvidence,
    EnrollmentPolicy, ExecutionContext, FrameOutcome, HostAuthority, HostKey, HostKeyAlgorithm,
    KnownHosts, ManagementAction, ManagementIdentity, PrintedFingerprint, ProgramPath,
    RejectionEvidence, RejectionObserver, RemoteHostId, RemoteVmAdapter, SealedFrame, SessionState,
};

type HostDelegation = CoordinatorDelegation<Arc<ManualClock>, GrantAll>;

const BUDGET: u64 = 100_000_000;
const ADDRESS: &str = "203.0.113.7:2222";
const AGENT: &str = "/opt/yougori/bin/yougori-control";
/// How long a test waits for one frame; far longer than any healthy answer.
const WAIT: Duration = Duration::from_secs(30);

/// OpenSSH's report of a changed host key for the run's target, then its exit with 255.
const HOST_KEY_CHANGED: &str = "\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n\
The fingerprint for the ED25519 key sent by the remote host is\r\n\
SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.\r\n\
Please contact your system administrator.\r\n\
ED25519 host key for [203.0.113.7]:2222 has changed and you have requested strict checking.\r\n\
Host key verification failed.\r\n";

/// An Ed25519 host key in SSH wire form, as `EnrolledHostKey` needs it.
fn wire_key(seed: u8) -> HostKey {
    HostKey::new(HostKeyAlgorithm::Ed25519, ed25519_blob(seed)).unwrap()
}

fn provider_api(key: &HostKey) -> EnrollmentEvidence {
    EnrollmentEvidence::ProviderApi {
        reported: key.fingerprint(),
    }
}

fn agent() -> ControlAgent {
    ControlAgent::new(ProgramPath::new(AGENT).unwrap())
}

fn ssh_limits(connect_timeout_seconds: u32) -> SshLimits {
    SshLimits::new(
        connect_timeout_seconds,
        10,
        2,
        Duration::from_secs(60),
        256 * 1024,
        256 * 1024,
    )
    .unwrap()
}

/// Limits with room for a whole test executable to start, even on a loaded machine.
fn patient() -> ControlLimits {
    ControlLimits::new(ssh_limits(10), WAIT, Duration::from_secs(10)).unwrap()
}

/// The silence deadline of the silence tests.
const SHORT_SILENCE: Duration = Duration::from_secs(5);

fn hasty() -> ControlLimits {
    ControlLimits::new(ssh_limits(1), SHORT_SILENCE, Duration::from_secs(10)).unwrap()
}

/// Kills the process `id` with exit code `code`, as something outside the engine would.
fn kill(id: u32, code: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    // SAFETY: plain Win32 calls on a handle opened here and closed once.
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, id) };
    assert!(!handle.is_null(), "client {id} not found");
    let terminated = unsafe { TerminateProcess(handle, code) };
    unsafe { CloseHandle(handle) };
    assert_ne!(terminated, 0, "client {id} not killed");
}

/// The adapter states these tests drive a run to, in lifecycle order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Planned,
    Provisioned,
    IdentityEnrolled,
    RuntimeConfirmed,
    Running,
    AuthorityEnded,
    Terminating,
}

/// One remote run of a dedicated provider VM (or a provider container), its host enrolled
/// with a wire-form key, and a management identity with every action. Another host is
/// enrolled first, with an identity of its own.
struct Run {
    world: HostWorld<Arc<ManualClock>>,
    authority: HostDelegation,
    provider: FakeProvider,
    ledger: SharedSpendLedger,
    known: KnownHosts,
    adapter: RemoteVmAdapter<Arc<ManualClock>>,
    host: RemoteHostId,
    identity: ManagementIdentity,
    other: ManagementIdentity,
    container: bool,
}

impl Run {
    fn new(container: bool) -> Self {
        let world = HostWorld::new(4 * HOUR);
        let authority = world.delegation();
        let ledger = SharedSpendLedger::new(SpendLedger::new());
        ledger
            .with(|book| book.open_account(account(), BUDGET))
            .unwrap();
        let (offering, request, execution) = if container {
            (container_offering(), explicit_container(), pod_execution())
        } else {
            (dedicated_offering(), vm_request(), parent())
        };
        let adapter = RemoteVmAdapter::plan(
            Arc::clone(&world.clock),
            attempt(1),
            execution,
            &request,
            &[offering],
            config(),
        )
        .unwrap();
        let host = FakeProvider::instance_for(&adapter.provision_request()).host();
        let mut known = KnownHosts::new();
        let other = known
            .enroll(
                host_id(2),
                &wire_key(2),
                provider_api(&wire_key(2)),
                EnrollmentPolicy::default(),
                world.now(),
            )
            .unwrap();
        let enrollment = known
            .enroll(
                host,
                &wire_key(1),
                provider_api(&wire_key(1)),
                EnrollmentPolicy::default(),
                world.now(),
            )
            .unwrap();
        Self {
            world,
            authority,
            provider: FakeProvider::default(),
            ledger,
            known,
            adapter,
            host,
            identity: identity_for(&enrollment, &ManagementAction::ALL),
            other: identity_for(&other, &ManagementAction::ALL),
            container,
        }
    }

    /// A dedicated-VM run driven to `stage`.
    fn at(stage: Stage) -> Self {
        Self::of(false, stage)
    }

    /// A run driven to `stage`; from running on, through a control session V12's
    /// fixtures open directly, not through the transport.
    fn of(container: bool, stage: Stage) -> Self {
        let mut run = Self::new(container);
        if stage >= Stage::Provisioned {
            run.adapter
                .reserve_spend(&run.ledger, &provision_effect(account(), 10_000_000, 1))
                .unwrap();
            run.adapter
                .provision(&mut run.provider, &run.ledger)
                .unwrap();
        }
        if stage >= Stage::IdentityEnrolled {
            run.adapter
                .enroll(&mut run.known, &wire_key(1), provider_api(&wire_key(1)))
                .unwrap();
        }
        if stage >= Stage::RuntimeConfirmed {
            run.confirm();
        }
        if stage >= Stage::Running {
            let session = ControlSession::open(
                run.adapter.identity().unwrap().clone(),
                session_id(9),
                session_key(9),
                control_key(9),
                run.world.now(),
            );
            run.adapter
                .connect(&run.known, &wire_key(1), session, &mut run.authority)
                .unwrap();
            run.adapter
                .launch(
                    &mut run.authority,
                    OperationId::new("op-remote").unwrap(),
                    None,
                )
                .unwrap();
        }
        match stage {
            Stage::AuthorityEnded => {
                run.world.advance(11 * MINUTE);
                assert!(run.adapter.check_authority(&mut run.authority).is_err());
            }
            Stage::Terminating => run.adapter.begin_termination(&mut run.authority).unwrap(),
            _ => {}
        }
        run
    }

    fn confirm(&mut self) {
        let instance = self.adapter.instance().unwrap().instance;
        if self.container {
            let offer = self
                .world
                .remote_offer(instance, ExecutionCategory::ProviderContainerRuntime);
            let admitted = self.adapter.confirm_runtime(&offer, None).unwrap();
            self.world
                .authorize_labelled(pod_execution(), admitted, HOUR)
                .unwrap();
        } else {
            let offer = self
                .world
                .remote_offer(instance, ExecutionCategory::VmSandbox);
            self.adapter.confirm_runtime(&offer, None).unwrap();
        }
        assert_eq!(self.adapter.state(), &AdapterState::RuntimeConfirmed);
    }

    fn open(
        &mut self,
        transport: &mut ControlTransport<'_>,
    ) -> Result<FrameOutcome, ControlTransportRefusal> {
        let identity = self.identity.clone();
        self.open_as(transport, &identity)
    }

    fn open_as(
        &mut self,
        transport: &mut ControlTransport<'_>,
        identity: &ManagementIdentity,
    ) -> Result<FrameOutcome, ControlTransportRefusal> {
        transport.open(
            &mut self.adapter,
            &mut self.authority,
            &self.known,
            identity,
        )
    }

    fn launch(
        &mut self,
        transport: &mut ControlTransport<'_>,
    ) -> Result<(), ControlTransportRefusal> {
        transport.launch(
            &mut self.adapter,
            &mut self.authority,
            &self.known,
            OperationId::new("op-remote").unwrap(),
            None,
        )
    }

    fn renew(
        &mut self,
        transport: &mut ControlTransport<'_>,
    ) -> Result<(), ControlTransportRefusal> {
        transport.renew(&mut self.adapter, &mut self.authority, &self.known)
    }

    fn receive(
        &mut self,
        transport: &mut ControlTransport<'_>,
    ) -> Result<Option<FrameOutcome>, ControlTransportRefusal> {
        transport.receive(&mut self.adapter, &mut self.authority, &self.known, WAIT)
    }

    fn close(&mut self, transport: &mut ControlTransport<'_>) -> Option<ControlEnd> {
        transport.close(&mut self.adapter, &mut self.authority, &self.known)
    }

    /// The end the next receive reports; the session must end within it.
    fn ended(&mut self, transport: &mut ControlTransport<'_>) -> ControlEnd {
        match self.receive(transport) {
            Err(ControlTransportRefusal::Ended { end }) => *end,
            other => panic!("the session did not end: {other:?}"),
        }
    }

    /// The state of the adapter's control session.
    fn session_state(&self) -> Option<SessionState> {
        self.adapter.control().map(ControlSession::state)
    }

    fn expires_at(&self) -> crate::foundation::ids::MonotonicTime {
        self.adapter.delegation().unwrap().expires_at()
    }
}

fn is_lost(state: Option<SessionState>) -> bool {
    matches!(state, Some(SessionState::Lost { .. }))
}

/// The client side: the files the client is rendered with and its working directory,
/// where the fake finds its script and leaves its record, log and runs.
struct Client {
    _scratch: Scratch,
    work: tempfile::TempDir,
    known_hosts: KnownHostsFile,
    identity_file: IdentityFile,
}

impl Client {
    fn new(run: &Run) -> Self {
        let scratch = Scratch::new();
        let target = SshTarget::new(run.host, authority(ADDRESS));
        let key = EnrolledHostKey::new(
            &run.known,
            target,
            HostKeyAlgorithm::Ed25519,
            ed25519_blob(1),
        )
        .unwrap();
        let known_hosts = KnownHostsFile::write(key, scratch.path("known_hosts")).unwrap();
        let identity_file = IdentityFile::new(mgmt_key(), scratch.path("id_ed25519"));
        std::fs::write(identity_file.path().as_path(), b"test key").unwrap();
        protect_identity_file(identity_file.path()).unwrap();
        let work = tempfile::Builder::new()
            .prefix("remote-ssh-control-")
            .tempdir()
            .unwrap();
        Self {
            _scratch: scratch,
            work,
            known_hosts,
            identity_file,
        }
    }

    fn transport<'a>(
        &self,
        invocation: &'a ControlInvocation,
        limits: ControlLimits,
    ) -> ControlTransport<'a> {
        ControlTransport::new(
            std::env::current_exe().unwrap(),
            self.work.path(),
            self.known_hosts.clone(),
            self.identity_file.clone(),
            limits,
            invocation,
        )
        .unwrap()
    }

    fn script(&self, script: &ControlScript) {
        std::fs::write(
            self.work.path().join(CONTROL_SCRIPT_FILE),
            serde_json::to_vec(script).unwrap(),
        )
        .unwrap();
    }

    fn has_record(&self) -> bool {
        self.work.path().join(CONTROL_RECORD_FILE).exists()
    }

    fn record(&self) -> Record {
        serde_json::from_slice(&std::fs::read(self.work.path().join(CONTROL_RECORD_FILE)).unwrap())
            .unwrap()
    }

    /// The session key the fake read: the first message on its stdin.
    fn key(&self) -> Vec<u8> {
        let stdin = self.record().stdin;
        assert_eq!(stdin[..4], 32u32.to_be_bytes());
        stdin[4..4 + CONTROL_KEY_BYTES].to_vec()
    }

    /// The host frames the fake accepted, its first frame first.
    fn log(&self) -> Vec<SealedFrame> {
        std::fs::read_to_string(self.work.path().join(CONTROL_LOG_FILE))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// How many times the fake was started.
    fn runs(&self) -> usize {
        std::fs::read_to_string(self.work.path().join(CONTROL_RUNS_FILE))
            .map(|text| text.lines().count())
            .unwrap_or(0)
    }
}

#[test]
fn a_session_opens_and_a_renewal_round_trips() {
    let mut run = Run::at(Stage::RuntimeConfirmed);
    let client = Client::new(&run);
    let invocation = agent().invocation(&run.identity, &run.known).unwrap();
    let mut transport = client.transport(&invocation, patient());
    client.script(&ControlScript::Serve { renew: true });

    // The remote's first frame, a heartbeat, is V12's to judge.
    assert_eq!(run.open(&mut transport), Ok(FrameOutcome::Heard));
    let session = transport.channel().unwrap().session();
    let control = run.adapter.control().unwrap();
    assert_eq!(control.id(), session);
    assert_eq!(control.state(), SessionState::Live);
    assert_eq!(control.identity(), run.adapter.identity().unwrap());
    assert_eq!(client.runs(), 1);

    // The client is the configured program with exactly the rendered arguments of V12's
    // supervise invocation of the agent, in a cleared environment.
    let record = client.record();
    assert_eq!(
        PathBuf::from(&record.program),
        std::env::current_exe().unwrap()
    );
    assert_eq!(record.arguments, transport.channel().unwrap().arguments());
    assert_eq!(record.arguments[..2], ["-F", "none"]);
    assert_eq!(record.arguments.last().unwrap(), &format!("'{AGENT}'"));
    assert_eq!(invocation.remote().action(), ManagementAction::SuperviseVm);
    assert!(record
        .environment
        .keys()
        .all(|name| CLIENT_ENVIRONMENT.contains(&name.as_str())));

    // Launch sends the first grant; the remote asks for a renewal, V12 renews the lease
    // and the transport sends the new grant, which the remote answers.
    run.launch(&mut transport).unwrap();
    assert_eq!(run.adapter.state(), &AdapterState::Running);
    let first_expiry = run.expires_at();
    run.world.advance(30 * SECOND);
    let Ok(Some(FrameOutcome::Renewed { grant })) = run.receive(&mut transport) else {
        panic!("no renewal");
    };
    assert_eq!(run.expires_at(), first_expiry.saturating_add(30 * SECOND));
    assert_eq!(run.receive(&mut transport), Ok(Some(FrameOutcome::Heard)));

    // The remote saw the host's first frame, the first grant and the renewed grant, each
    // sealed under the key it was sent, on this session and identity, counting up.
    let log = client.log();
    assert_eq!(log.len(), 3);
    assert_eq!(log[0].frame.body, ControlBody::Heartbeat);
    assert!(matches!(log[1].frame.body, ControlBody::Grant { .. }));
    assert_eq!(log[2], grant);
    for (sequence, frame) in log.iter().enumerate() {
        assert_eq!(frame.frame.sequence, u64::try_from(sequence).unwrap());
        assert_eq!(frame.frame.session, session);
        assert_eq!(
            frame.frame.identity,
            run.adapter.identity().unwrap().digest()
        );
    }

    // Closing ends the remote by closing its stdin, and V12 marks the session lost.
    let end = run.close(&mut transport).unwrap();
    assert_eq!(end.session, session);
    assert_eq!(end.reason, ControlEndReason::Closed);
    assert_eq!(end.termination, SshTermination::Exited { code: 0 });
    assert_eq!(end.outcome, SshOutcome::RemoteExit { code: 0 });
    assert_eq!(end.host_key, None);
    assert!(is_lost(run.session_state()));
    assert!(transport.channel().is_none());
    assert_eq!(
        run.receive(&mut transport),
        Err(ControlTransportRefusal::NoChannel)
    );
    assert_eq!(
        run.renew(&mut transport),
        Err(ControlTransportRefusal::NoChannel)
    );
    assert!(run.close(&mut transport).is_none());
}

#[test]
fn the_session_key_goes_over_stdin_only_and_never_into_argv_debug_or_errors() {
    let mut run = Run::at(Stage::RuntimeConfirmed);
    let client = Client::new(&run);
    let invocation = agent().invocation(&run.identity, &run.known).unwrap();
    let mut transport = client.transport(&invocation, patient());
    client.script(&ControlScript::Serve { renew: false });
    assert_eq!(run.open(&mut transport), Ok(FrameOutcome::Heard));
    let session = transport.channel().unwrap().session();

    // Stdin: the key behind its length, then the host's first frame, a heartbeat sealed
    // under that key on the new session, which names the run's identity.
    let record = client.record();
    let key = client.key();
    assert_eq!(key.len(), CONTROL_KEY_BYTES);
    let rest = &record.stdin[4 + CONTROL_KEY_BYTES..];
    let length = usize::try_from(u32::from_be_bytes(rest[..4].try_into().unwrap())).unwrap();
    assert_eq!(rest.len(), 4 + length);
    let hello: SealedFrame = serde_json::from_slice(&rest[4..]).unwrap();
    assert_eq!(hello.frame.session, session);
    assert_eq!(hello.frame.sequence, 0);
    assert_eq!(hello.frame.body, ControlBody::Heartbeat);
    assert_eq!(
        hello.frame.identity,
        run.adapter.identity().unwrap().digest()
    );
    let control_key = ControlKey::new(key.clone()).unwrap();
    assert_eq!(hello.frame.seal(&control_key), hello);
    // V12's public binding of the session is one the remote can compute.
    assert_eq!(
        run.adapter.control().unwrap().session_key(),
        DigestBuilder::new(CONTROL_BINDING_DOMAIN)
            .digest(session.digest())
            .bytes(&key)
            .finish()
    );

    let debug_bytes = format!("{key:?}");
    let decimal = &debug_bytes[1..debug_bytes.len() - 1];
    let assert_hidden = |text: &str| {
        assert!(find_encoded(text.as_bytes(), &key).is_none(), "{text}");
        assert!(!text.contains(decimal), "{text}");
    };
    assert_hidden(&record.program);
    record.arguments.iter().for_each(|word| assert_hidden(word));
    for (name, value) in &record.environment {
        assert_hidden(name);
        assert_hidden(value);
    }
    assert_hidden(&format!("{transport:?}"));
    assert_hidden(&format!("{:?}", transport.channel()));
    assert_hidden(&format!("{:?}", run.adapter.control()));
    assert_hidden(&format!("{invocation:?}"));

    // Errors: a refusal while the channel is open, and the end of the session.
    let refusal = run.open(&mut transport).unwrap_err();
    assert_eq!(refusal, ControlTransportRefusal::ChannelOpen);
    assert_hidden(&format!("{refusal:?} {refusal}"));
    let end = run.close(&mut transport).unwrap();
    assert_hidden(&format!("{end:?}"));
    assert_hidden(&serde_json::to_string(&end).unwrap());

    // A session that ends on a refusal shows no key either, its own or the first one.
    client.script(&ControlScript::Misbehave {
        fault: Fault::Tampered,
    });
    assert_eq!(run.open(&mut transport), Ok(FrameOutcome::Heard));
    let second = client.key();
    assert_ne!(second, key);
    let refusal = run.receive(&mut transport).unwrap_err();
    assert!(matches!(refusal, ControlTransportRefusal::Ended { .. }));
    for text in [
        format!("{refusal:?}"),
        refusal.to_string(),
        serde_json::to_string(&refusal).unwrap(),
    ] {
        assert_hidden(&text);
        assert!(find_encoded(text.as_bytes(), &second).is_none(), "{text}");
    }
}

#[test]
fn an_oversize_tampered_replayed_or_foreign_frame_ends_the_session() {
    let control = |refusal: ControlRefusal| ControlEndReason::Refused {
        refusal: Box::new(AdapterRefusal::Control { refusal }),
    };
    for (fault, expected) in [
        (
            Fault::Oversize,
            ControlEndReason::FrameOutOfBounds {
                declared: u64::from(MAX_CONTROL_FRAME_BYTES) + 1,
                max_bytes: u64::from(MAX_CONTROL_FRAME_BYTES),
            },
        ),
        (Fault::Tampered, control(ControlRefusal::Tampered)),
        (
            Fault::Replayed,
            control(ControlRefusal::Replayed {
                sequence: 0,
                next_expected: 1,
            }),
        ),
        (Fault::OtherSession, control(ControlRefusal::OtherSession)),
        (Fault::StaleIdentity, control(ControlRefusal::StaleIdentity)),
        (Fault::UnknownField, ControlEndReason::Malformed),
    ] {
        let mut run = Run::at(Stage::RuntimeConfirmed);
        let client = Client::new(&run);
        let invocation = agent().invocation(&run.identity, &run.known).unwrap();
        let mut transport = client.transport(&invocation, patient());
        client.script(&ControlScript::Misbehave { fault });
        assert_eq!(
            run.open(&mut transport),
            Ok(FrameOutcome::Heard),
            "{fault:?}"
        );
        let session = transport.channel().unwrap().session();

        let end = run.ended(&mut transport);
        assert_eq!(end.reason, expected, "{fault:?}");
        assert_eq!(end.session, session);
        assert!(!end.outcome.succeeded());
        assert!(is_lost(run.session_state()), "{fault:?}");
        assert!(transport.channel().is_none());

        // Nothing is sent on the lost session, and V12 delegates nothing over it.
        assert_eq!(
            run.launch(&mut transport),
            Err(ControlTransportRefusal::NoChannel)
        );
        assert!(matches!(
            run.adapter.launch(
                &mut run.authority,
                OperationId::new("op-remote").unwrap(),
                None
            ),
            Err(AdapterRefusal::ControlNotLive { .. })
        ));
        assert_eq!(run.adapter.state(), &AdapterState::RuntimeConfirmed);
    }
}

#[test]
fn the_end_of_the_stream_marks_the_session_lost() {
    let mut run = Run::at(Stage::RuntimeConfirmed);
    let client = Client::new(&run);
    let invocation = agent().invocation(&run.identity, &run.known).unwrap();
    let mut transport = client.transport(&invocation, patient());
    client.script(&ControlScript::Exit {
        hello: true,
        code: 0,
    });
    assert_eq!(run.open(&mut transport), Ok(FrameOutcome::Heard));
    let end = run.ended(&mut transport);
    assert!(
        matches!(
            end.reason,
            ControlEndReason::EndOfStream | ControlEndReason::ClientExited
        ),
        "{end:?}"
    );
    assert_eq!(end.termination, SshTermination::Exited { code: 0 });
    assert_eq!(end.outcome, SshOutcome::RemoteExit { code: 0 });
    assert!(is_lost(run.session_state()));
    assert!(transport.channel().is_none());
}

#[test]
fn a_killed_client_marks_the_session_lost() {
    let mut run = Run::at(Stage::Running);
    let client = Client::new(&run);
    let invocation = agent().invocation(&run.identity, &run.known).unwrap();
    let mut transport = client.transport(&invocation, patient());
    client.script(&ControlScript::Silent { hello: true });
    assert_eq!(run.open(&mut transport), Ok(FrameOutcome::Heard));
    kill(transport.channel().unwrap().client_id(), 77);
    let end = run.ended(&mut transport);
    assert!(
        matches!(
            end.reason,
            ControlEndReason::EndOfStream | ControlEndReason::ClientExited
        ),
        "{end:?}"
    );
    assert_eq!(end.termination, SshTermination::Exited { code: 77 });
    assert!(is_lost(run.session_state()));
    // Renewals stop with the session; the delegation runs out on its own.
    assert!(matches!(
        run.adapter.renew(&mut run.authority),
        Err(AdapterRefusal::ControlNotLive { .. })
    ));
    assert_eq!(run.adapter.state(), &AdapterState::Running);
}

#[test]
fn shared_rejection_or_reenrollment_ends_an_already_open_channel_before_work_or_renewal() {
    for change in ["reject", "retire", "reenroll"] {
        for operation in ["launch", "renew", "receive"] {
            let mut run = Run::at(Stage::RuntimeConfirmed);
            let client = Client::new(&run);
            let invocation = agent().invocation(&run.identity, &run.known).unwrap();
            let mut transport = client.transport(&invocation, patient());
            client.script(&ControlScript::Silent { hello: true });
            assert_eq!(run.open(&mut transport), Ok(FrameOutcome::Heard));
            if operation != "launch" {
                run.launch(&mut transport).unwrap();
            }
            let lease = run.adapter.delegation().cloned();
            if change == "reject" {
                run.known
                    .record_rejection(
                        &run.host,
                        run.identity.enrollment(),
                        RejectionObserver::ManagementSsh,
                        RejectionEvidence::SshUnverified,
                        run.world.now(),
                    )
                    .unwrap();
            } else {
                run.known.retire(&run.host);
                if change == "reenroll" {
                    run.known
                        .enroll(
                            run.host,
                            &wire_key(1),
                            provider_api(&wire_key(1)),
                            EnrollmentPolicy::default(),
                            run.world.now(),
                        )
                        .unwrap();
                }
            }
            let failed = match operation {
                "launch" => run.launch(&mut transport),
                "renew" => run.renew(&mut transport),
                _ => run.receive(&mut transport).map(|_| ()),
            };
            assert!(
                matches!(failed, Err(ControlTransportRefusal::Ended { .. })),
                "{change}/{operation}"
            );
            assert!(transport.channel().is_none());
            assert_eq!(run.adapter.state(), &AdapterState::Terminating);
            if let Some(Delegation::Lease { lease }) = lease {
                assert!(run.authority.check(lease.id()).is_err());
            } else {
                assert!(run.adapter.delegation().is_none());
            }
        }
    }
}

#[test]
fn silence_past_the_deadline_marks_the_session_lost() {
    // Silent after its first frame: the deadline counts from the last frame.
    let mut run = Run::at(Stage::RuntimeConfirmed);
    let client = Client::new(&run);
    let invocation = agent().invocation(&run.identity, &run.known).unwrap();
    let mut transport = client.transport(&invocation, hasty());
    client.script(&ControlScript::Silent { hello: true });
    assert_eq!(run.open(&mut transport), Ok(FrameOutcome::Heard));
    let started = Instant::now();
    let end = run.ended(&mut transport);
    let ControlEndReason::Silent { silent_for_ms } = end.reason else {
        panic!("not silence: {end:?}");
    };
    assert!(silent_for_ms >= 5_000, "{silent_for_ms}");
    assert!(started.elapsed() < WAIT);
    assert_eq!(end.termination, SshTermination::DeadlineReached);
    assert_eq!(
        end.outcome,
        SshOutcome::TimedOut {
            phase: TimeoutPhase::Deadline
        }
    );
    assert!(is_lost(run.session_state()));

    // Silent from the start: the first frame is due within the deadline too.
    client.script(&ControlScript::Silent { hello: false });
    let refusal = run.open(&mut transport).unwrap_err();
    let ControlTransportRefusal::Ended { end } = refusal else {
        panic!("not ended: {refusal:?}");
    };
    assert!(
        matches!(end.reason, ControlEndReason::Silent { .. }),
        "{end:?}"
    );
    assert!(is_lost(run.session_state()));
    assert_eq!(client.runs(), 2);
}

#[test]
fn a_remote_that_stops_reading_stalls_the_writes_and_ends_the_session() {
    let mut run = Run::at(Stage::RuntimeConfirmed);
    let client = Client::new(&run);
    let invocation = agent().invocation(&run.identity, &run.known).unwrap();
    let limits = ControlLimits::new(ssh_limits(10), WAIT, Duration::from_secs(1)).unwrap();
    let mut transport = client.transport(&invocation, limits);
    client.script(&ControlScript::Deaf { seconds: 60 });
    assert_eq!(run.open(&mut transport), Ok(FrameOutcome::Heard));
    run.launch(&mut transport).unwrap();
    // Grants pile up in the pipe until a write cannot finish within the write wait.
    let mut renewals = 0;
    let end = loop {
        match run.renew(&mut transport) {
            Ok(()) => renewals += 1,
            Err(ControlTransportRefusal::Ended { end }) => break *end,
            Err(other) => panic!("{other:?}"),
        }
        assert!(renewals < 10_000, "the writes never stalled");
    };
    assert_eq!(end.reason, ControlEndReason::WriteStalled);
    assert_eq!(end.termination, SshTermination::NoExitStatus);
    assert!(is_lost(run.session_state()));
    assert!(transport.channel().is_none());
}

#[test]
fn stderr_past_its_bound_ends_the_session() {
    let mut run = Run::at(Stage::RuntimeConfirmed);
    let client = Client::new(&run);
    let invocation = agent().invocation(&run.identity, &run.known).unwrap();
    let ssh = SshLimits::new(10, 10, 2, Duration::from_secs(60), 1024, 1024).unwrap();
    let limits = ControlLimits::new(ssh, WAIT, Duration::from_secs(10)).unwrap();
    let mut transport = client.transport(&invocation, limits);
    client.script(&ControlScript::Chatter { bytes: 64 * 1024 });
    // The two pipes are read apart, so the flood may be seen before the first frame.
    let end = match run.open(&mut transport) {
        Ok(FrameOutcome::Heard) => run.ended(&mut transport),
        Err(ControlTransportRefusal::Ended { end }) => *end,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        end.reason,
        ControlEndReason::StderrOverBound { max_bytes: 1024 }
    );
    assert_eq!(end.stderr.len(), 1025);
    assert_eq!(
        end.outcome,
        SshOutcome::OutputOverBound {
            stream: OutputStream::Stderr,
            max_bytes: 1024
        }
    );
    assert!(is_lost(run.session_state()));
}

#[test]
fn a_host_key_mismatch_on_stderr_ends_the_session_and_the_authority() {
    let mut run = Run::at(Stage::RuntimeConfirmed);
    let client = Client::new(&run);
    let invocation = agent().invocation(&run.identity, &run.known).unwrap();
    let mut transport = client.transport(&invocation, patient());
    client.script(&ControlScript::Serve { renew: false });
    assert_eq!(run.open(&mut transport), Ok(FrameOutcome::Heard));
    run.launch(&mut transport).unwrap();
    assert_eq!(run.receive(&mut transport), Ok(Some(FrameOutcome::Heard)));
    let Some(Delegation::Lease { lease }) = run.adapter.delegation().cloned() else {
        panic!("no lease");
    };
    run.close(&mut transport).unwrap();

    // The reconnect meets another host key: the client says so on stderr and exits 255.
    client.script(&ControlScript::Fail {
        stderr: HOST_KEY_CHANGED.to_owned(),
        code: 255,
    });
    let refusal = run.open(&mut transport).unwrap_err();
    let ControlTransportRefusal::Ended { end } = refusal else {
        panic!("not ended: {refusal:?}");
    };
    let evidence = HostKeyEvidence::Changed {
        reported: Some(PUBLISHED_ED25519_SHA256.to_owned()),
    };
    let enrolled = wire_key(1).fingerprint();
    assert_eq!(end.termination, SshTermination::Exited { code: 255 });
    assert_eq!(
        end.outcome,
        SshOutcome::HostKeyMismatch {
            host: run.host,
            enrolled,
            evidence: evidence.clone(),
        }
    );
    let rejected = RejectedHostKey {
        host: run.host,
        enrolled,
        evidence,
    };
    assert_eq!(end.host_key.as_ref(), Some(&rejected));
    assert_eq!(transport.rejected(), Some(&rejected));

    // V12 recorded the rejection and ended the authority at once: the lease is released.
    let generation = run.adapter.identity().unwrap().enrollment;
    let rejection = run.known.rejection(&run.host, generation).unwrap();
    assert_eq!(rejection.observer, RejectionObserver::ManagementSsh);
    assert_eq!(
        rejection.evidence,
        RejectionEvidence::SshKeyChanged {
            printed: Some(PrintedFingerprint::new(PUBLISHED_ED25519_SHA256).unwrap()),
        }
    );
    assert_eq!(
        run.adapter.state(),
        &AdapterState::AuthorityEnded {
            reason: AuthorityEnd::HostKeyRejected {
                host: run.host,
                generation,
                observer: RejectionObserver::ManagementSsh,
            }
        }
    );
    assert!(run.authority.check(lease.id()).is_err());
    assert!(is_lost(run.session_state()));

    // The transport opens nothing more.
    client.script(&ControlScript::Serve { renew: false });
    let runs = client.runs();
    assert_eq!(
        run.open(&mut transport),
        Err(ControlTransportRefusal::HostKeyRejected {
            host: run.host,
            enrolled,
        })
    );
    assert_eq!(client.runs(), runs);
}

#[test]
fn a_reconnect_gets_a_new_key_and_session_and_cannot_revive_expired_authority() {
    let mut run = Run::at(Stage::RuntimeConfirmed);
    let client = Client::new(&run);
    let invocation = agent().invocation(&run.identity, &run.known).unwrap();
    let mut transport = client.transport(&invocation, patient());
    client.script(&ControlScript::Serve { renew: false });
    assert_eq!(run.open(&mut transport), Ok(FrameOutcome::Heard));
    let first_key = client.key();
    let first_session = transport.channel().unwrap().session();
    run.launch(&mut transport).unwrap();
    assert_eq!(run.receive(&mut transport), Ok(Some(FrameOutcome::Heard)));
    run.close(&mut transport).unwrap();

    // The lost session renews nothing, through the transport or V12.
    assert_eq!(
        run.renew(&mut transport),
        Err(ControlTransportRefusal::NoChannel)
    );
    assert!(matches!(
        run.adapter.renew(&mut run.authority),
        Err(AdapterRefusal::ControlNotLive { .. })
    ));

    // A reconnect is a new client with a new key and a new session.
    assert_eq!(run.open(&mut transport), Ok(FrameOutcome::Heard));
    assert_eq!(client.runs(), 2);
    let second_key = client.key();
    let second_session = transport.channel().unwrap().session();
    assert_ne!(second_key, first_key);
    assert_ne!(second_session, first_session);
    let control = run.adapter.control().unwrap();
    assert_eq!(control.id(), second_session);
    assert_eq!(control.state(), SessionState::Live);
    // A frame of the lost session fails the new one's seal.
    let old = ControlFrame {
        session: first_session,
        identity: run.adapter.identity().unwrap().digest(),
        sequence: 7,
        body: ControlBody::Heartbeat,
    }
    .seal(&ControlKey::new(first_key).unwrap());
    assert_eq!(
        run.adapter.handle_frame(&old, &mut run.authority),
        Err(AdapterRefusal::Control {
            refusal: ControlRefusal::Tampered
        })
    );

    // The new session renews while the authority is current.
    run.world.advance(30 * SECOND);
    run.renew(&mut transport).unwrap();
    assert_eq!(run.receive(&mut transport), Ok(Some(FrameOutcome::Heard)));
    let log = client.log();
    assert_eq!(log.len(), 2);
    assert!(log
        .iter()
        .all(|frame| frame.frame.session == second_session));

    // Lost again, and the authority expires meanwhile: the reconnect is refused by V12,
    // which ends the authority, and nothing is started.
    run.close(&mut transport).unwrap();
    run.world.advance(11 * MINUTE);
    let refusal = run.open(&mut transport).unwrap_err();
    let ControlTransportRefusal::Connect { refusal } = refusal else {
        panic!("not V12's refusal: {refusal:?}");
    };
    assert!(
        matches!(*refusal, AdapterRefusal::Authority { .. }),
        "{refusal:?}"
    );
    assert_eq!(client.runs(), 2);
    assert!(transport.channel().is_none());
    assert!(matches!(
        run.adapter.state(),
        AdapterState::AuthorityEnded {
            reason: AuthorityEnd::LeaseRefused { .. }
        }
    ));
    assert_eq!(
        run.renew(&mut transport),
        Err(ControlTransportRefusal::NoChannel)
    );
    assert!(run.adapter.renew(&mut run.authority).is_err());
    let refusal = run.open(&mut transport).unwrap_err();
    assert!(
        matches!(&refusal, ControlTransportRefusal::Connect { refusal } if matches!(**refusal, AdapterRefusal::InvalidStep { .. })),
        "{refusal:?}"
    );
    assert_eq!(client.runs(), 2);
}

#[test]
fn a_state_where_v12_refuses_opens_nothing() {
    let invalid = |run: &Run| ControlTransportRefusal::Connect {
        refusal: Box::new(AdapterRefusal::InvalidStep {
            state: run.adapter.state().clone(),
            step: AdapterStep::Connect,
        }),
    };
    for stage in [
        Stage::Planned,
        Stage::Provisioned,
        Stage::IdentityEnrolled,
        Stage::AuthorityEnded,
        Stage::Terminating,
    ] {
        let mut run = Run::at(stage);
        let client = Client::new(&run);
        let invocation = agent().invocation(&run.identity, &run.known).unwrap();
        let mut transport = client.transport(&invocation, patient());
        client.script(&ControlScript::Serve { renew: false });
        let expected = if stage < Stage::IdentityEnrolled {
            ControlTransportRefusal::NotEnrolled
        } else {
            invalid(&run)
        };
        let before = run
            .adapter
            .control()
            .map(|control| (control.id(), control.state()));
        let state = run.adapter.state().clone();
        assert_eq!(run.open(&mut transport), Err(expected), "{stage:?}");
        assert_eq!(client.runs(), 0, "{stage:?}");
        assert!(!client.has_record());
        assert!(transport.channel().is_none());
        assert_eq!(
            run.adapter
                .control()
                .map(|control| (control.id(), control.state())),
            before
        );
        assert_eq!(run.adapter.state(), &state);
    }

    // A management identity for another host, and a provider-container run, whose
    // container V12 never runs a supervise call in.
    let mut run = Run::at(Stage::RuntimeConfirmed);
    let client = Client::new(&run);
    let invocation = agent().invocation(&run.identity, &run.known).unwrap();
    let mut transport = client.transport(&invocation, patient());
    client.script(&ControlScript::Serve { renew: false });
    let other = run.other.clone();
    assert_eq!(
        run.open_as(&mut transport, &other),
        Err(ControlTransportRefusal::WrongHost {
            run: run.host,
            other: host_id(2),
        })
    );
    let mut container = Run::of(true, Stage::RuntimeConfirmed);
    let container_client = Client::new(&container);
    let invocation = agent()
        .invocation(&container.identity, &container.known)
        .unwrap();
    let mut transport = container_client.transport(&invocation, patient());
    container_client.script(&ControlScript::Serve { renew: false });
    assert_eq!(
        container.open(&mut transport),
        Err(ControlTransportRefusal::ContextForAnotherKind {
            context: ExecutionContext::RemoteHostShell {
                host: container.host
            },
        })
    );
    assert_eq!(client.runs() + container_client.runs(), 0);
    assert!(run.adapter.control().is_none() && container.adapter.control().is_none());
}

#[test]
fn control_limits_are_checked() {
    let ssh = ssh_limits(10);
    assert_eq!(
        ControlLimits::new(ssh, Duration::from_millis(999), Duration::from_secs(1)),
        Err(ControlLimitsRefusal::SilenceOutOfRange {
            min_seconds: 1,
            max_seconds: MAX_CONTROL_SILENCE.as_secs(),
        })
    );
    assert!(matches!(
        ControlLimits::new(ssh, MAX_CONTROL_SILENCE + SECOND, Duration::from_secs(1)),
        Err(ControlLimitsRefusal::SilenceOutOfRange { .. })
    ));
    assert_eq!(
        ControlLimits::new(ssh, Duration::from_secs(9), Duration::from_secs(1)),
        Err(ControlLimitsRefusal::SilenceBeforeConnectTimeout)
    );
    assert!(matches!(
        ControlLimits::new(ssh, Duration::from_secs(10), Duration::ZERO),
        Err(ControlLimitsRefusal::WriteWaitOutOfRange { .. })
    ));
    let limits = ControlLimits::new(ssh, Duration::from_secs(10), Duration::from_secs(1)).unwrap();
    assert_eq!(limits.ssh(), ssh);
    assert_eq!(limits.max_silence(), Duration::from_secs(10));
    assert_eq!(limits.write_wait(), Duration::from_secs(1));
    assert_eq!(ControlLimits::STANDARD.ssh(), SshLimits::STANDARD);
    assert_eq!(
        ControlLimits::new(
            SshLimits::STANDARD,
            ControlLimits::STANDARD.max_silence(),
            ControlLimits::STANDARD.write_wait()
        ),
        Ok(ControlLimits::STANDARD)
    );
}
