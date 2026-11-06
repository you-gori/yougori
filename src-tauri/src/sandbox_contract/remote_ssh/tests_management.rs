//! Tests for management calls bound to V12's remote VM adapter (M16C; VM-W41 acceptance
//! "remote reconnect cannot revive expired authority; capability evidence distinguishes
//! host shell from VM workload"; VM part §6.2, §6.3; VM-D5, VM-D14).
//!
//! A real [`RemoteVmAdapter`] runs on V12's fakes and a real CORE-04 coordinator. Its host
//! is enrolled with a wire-form Ed25519 key, so the `known_hosts` file can be written for
//! it, and the SSH port is scripted: it records every argv and stdin and answers with
//! queued outputs. Nothing runs `ssh` or opens a socket.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use super::fakes::{
    authority, ed25519_blob, exited, helper, host_id, identity_for, launch_command, mgmt_key,
    Scratch,
};
use super::invocation::{IdentityFile, SshInvocation, SshLimits};
use super::known_hosts::{EnrolledHostKey, KnownHostsFile, SshTarget};
use super::management::{
    ManagementCall, ManagementCallRefusal, ManagementChannel, ProbeResult, RejectedHostKey,
    KVM_DEVICE, TEST_PROGRAM,
};
use super::outcome::{ConnectionFailure, HostKeyEvidence, SshOutcome, SshOutput, SshPort};
use super::protection::protect_identity_file;
use crate::foundation::coordination::{LeaseRefusal, RevocationMilestone};
use crate::foundation::ids::{ExecutionCategory, ManualClock, OperationId};
use crate::sandbox_contract::files::LifetimeRefusal;
use crate::sandbox_contract::policy::SecurityPredicate;
use crate::sandbox_contract::provider::{SharedSpendLedger, SpendLedger};
use crate::sandbox_contract::remote::fakes::{
    account, attempt, config, container_offering, control_key, dedicated_offering,
    explicit_container, metal_offering, parent, pod_execution, provision_effect, session_id,
    session_key, vm_id, vm_request, FakeProvider, GrantAll, HostWorld, HOUR, MINUTE, SECOND,
};
use crate::sandbox_contract::remote::ManagementAction::{
    CollectLogs, LaunchVm, ReplaceJupyterPassword, SuperviseVm, TerminateVm,
};
use crate::sandbox_contract::remote::{
    replace_jupyter_password, AdapterRefusal, AdapterState, AdapterStep, AuthorityEnd, ControlBody,
    ControlFrame, ControlSession, CoordinatorDelegation, Delegation, EnrollmentEvidence,
    EnrollmentPolicy, ExecutionContext, FrameOutcome, HostEnrollment, HostKey, HostKeyAlgorithm,
    KnownHosts, ManagementAction, ManagementIdentity, OptionTerminator, RemoteCapability,
    RemoteCapabilityEvidence, RemoteCommand, RemoteEvidenceRefusal, RemoteHostId, RemoteInvocation,
    RemoteSecret, RemoteVmAdapter,
};

type HostDelegation = CoordinatorDelegation<Arc<ManualClock>, GrantAll>;

const BUDGET: u64 = 100_000_000;
const ADDRESS: &str = "203.0.113.7:2222";
const PASSWORD: &[u8] = b"replacement-jupyter-password";
const HOST_KEY_FAILED: &str = "Host key verification failed.\r\n";

/// What the scripted port saw, and the outputs it still has to give.
#[derive(Debug, Default)]
struct Script {
    replies: VecDeque<SshOutput>,
    argvs: Vec<Vec<String>>,
    stdins: Vec<Option<Vec<u8>>>,
}

/// A port that records every argv and stdin and answers with the queued outputs, exit 0
/// once none is queued. Its state is shared, so a test queues replies and reads what it
/// saw while the channel owns it.
#[derive(Clone, Debug, Default)]
struct ScriptedPort(Rc<RefCell<Script>>);

impl ScriptedPort {
    fn reply(&self, output: SshOutput) {
        self.0.borrow_mut().replies.push_back(output);
    }

    fn calls(&self) -> usize {
        self.0.borrow().argvs.len()
    }

    fn last_argv(&self) -> Vec<String> {
        self.0.borrow().argvs.last().unwrap().clone()
    }

    fn last_stdin(&self) -> Option<Vec<u8>> {
        self.0.borrow().stdins.last().unwrap().clone()
    }
}

impl SshPort for ScriptedPort {
    fn run(&mut self, invocation: &SshInvocation<'_>) -> SshOutput {
        let mut script = self.0.borrow_mut();
        script.argvs.push(invocation.argv().to_vec());
        script.stdins.push(
            invocation
                .stdin()
                .map(|stdin| stdin.expose_to_transport().to_vec()),
        );
        script.replies.pop_front().unwrap_or_else(|| exited(0, ""))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A dedicated provider VM: the provider's VM is the sandbox.
    Dedicated,
    /// A bare-metal host that launches the per-sandbox VM.
    Metal,
    /// A provider container, the labelled runtime (VM-D5).
    Container,
}

impl Kind {
    const ALL: [Self; 3] = [Self::Dedicated, Self::Metal, Self::Container];
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
    Terminated,
}

impl Stage {
    const ALL: [Self; 8] = [
        Self::Planned,
        Self::Provisioned,
        Self::IdentityEnrolled,
        Self::RuntimeConfirmed,
        Self::Running,
        Self::AuthorityEnded,
        Self::Terminating,
        Self::Terminated,
    ];
}

fn stage_of(state: &AdapterState) -> Stage {
    match state {
        AdapterState::Planned => Stage::Planned,
        AdapterState::Provisioned => Stage::Provisioned,
        AdapterState::IdentityEnrolled => Stage::IdentityEnrolled,
        AdapterState::RuntimeConfirmed => Stage::RuntimeConfirmed,
        AdapterState::Running => Stage::Running,
        AdapterState::AuthorityEnded { .. } => Stage::AuthorityEnded,
        AdapterState::Terminating => Stage::Terminating,
        AdapterState::Terminated => Stage::Terminated,
        other => panic!("not a stage of these tests: {other:?}"),
    }
}

/// The adapter's refusal inside an `Authority` refusal.
fn authority_refusal(refusal: &ManagementCallRefusal) -> Option<&AdapterRefusal> {
    match refusal {
        ManagementCallRefusal::Authority { refusal } => Some(refusal.as_ref()),
        _ => None,
    }
}

/// An Ed25519 host key in SSH wire form, as `EnrolledHostKey` needs it.
fn wire_key(seed: u8) -> HostKey {
    HostKey::new(HostKeyAlgorithm::Ed25519, ed25519_blob(seed)).unwrap()
}

fn provider_api(key: &HostKey) -> EnrollmentEvidence {
    EnrollmentEvidence::ProviderApi {
        reported: key.fingerprint(),
    }
}

/// `action` in `context` under `identity`: V12's typed Jupyter password replacement, the
/// launch fixture, or the helper with one flag.
fn invocation(
    identity: &ManagementIdentity,
    known: &KnownHosts,
    action: ManagementAction,
    context: ExecutionContext,
) -> RemoteInvocation {
    let flag = match action {
        ReplaceJupyterPassword => {
            return replace_jupyter_password(
                identity,
                known,
                context,
                &helper(),
                RemoteSecret::new(PASSWORD.to_vec()),
            )
            .unwrap()
        }
        LaunchVm => {
            return RemoteInvocation::new(identity, known, action, context, &launch_command())
                .unwrap()
        }
        SuperviseVm => "--supervise-vm",
        TerminateVm => "--terminate-vm",
        CollectLogs => "--collect-logs",
    };
    let command = RemoteCommand::new(helper(), OptionTerminator::DoubleDash)
        .flag(flag)
        .unwrap();
    RemoteInvocation::new(identity, known, action, context, &command).unwrap()
}

/// A channel for `host` with a fresh `known_hosts` file named `name` for its wire key.
fn channel_for(
    known: &KnownHosts,
    host: RemoteHostId,
    scratch: &Scratch,
    name: &str,
    limits: SshLimits,
) -> ManagementChannel<ScriptedPort> {
    let target = SshTarget::new(host, authority(ADDRESS));
    let key =
        EnrolledHostKey::new(known, target, HostKeyAlgorithm::Ed25519, ed25519_blob(1)).unwrap();
    let known_hosts = KnownHostsFile::write(key, scratch.path(name)).unwrap();
    let identity_file = IdentityFile::new(mgmt_key(), scratch.path("id_ed25519"));
    std::fs::write(identity_file.path().as_path(), b"test key").unwrap();
    protect_identity_file(identity_file.path()).unwrap();
    ManagementChannel::new(ScriptedPort::default(), known_hosts, identity_file, limits)
}

/// One remote run, its host's enrollment, a management identity with every action and a
/// channel over a scripted port.
///
/// The run's host key is in `known` from the start, as the provider reports it; the
/// adapter's own enrollment of the same key returns that enrollment. So before the
/// adapter enrolls, the host is known but the run has no identity. Another host is
/// enrolled first, so the run's enrollment is not the first generation.
struct Fixture {
    kind: Kind,
    world: HostWorld<Arc<ManualClock>>,
    authority: HostDelegation,
    provider: FakeProvider,
    ledger: SharedSpendLedger,
    known: KnownHosts,
    adapter: RemoteVmAdapter<Arc<ManualClock>>,
    /// The run's host, as the provider creates it.
    host: RemoteHostId,
    identity: ManagementIdentity,
    /// A management identity for another enrolled host.
    other: ManagementIdentity,
    channel: ManagementChannel<ScriptedPort>,
    scratch: Scratch,
    files: u32,
    session_number: u8,
    remote_sequence: u64,
}

impl Fixture {
    fn new(kind: Kind) -> Self {
        let world = HostWorld::new(4 * HOUR);
        let authority = world.delegation();
        let ledger = SharedSpendLedger::new(SpendLedger::new());
        ledger
            .with(|book| book.open_account(account(), BUDGET))
            .unwrap();
        let (offering, request, execution) = match kind {
            Kind::Dedicated => (dedicated_offering(), vm_request(), parent()),
            Kind::Metal => (metal_offering(), vm_request(), parent()),
            Kind::Container => (container_offering(), explicit_container(), pod_execution()),
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
        let scratch = Scratch::new();
        let channel = channel_for(&known, host, &scratch, "known_hosts", SshLimits::STANDARD);
        Self {
            kind,
            world,
            authority,
            provider: FakeProvider::default(),
            ledger,
            identity: identity_for(&enrollment, &ManagementAction::ALL),
            other: identity_for(&other, &ManagementAction::ALL),
            known,
            adapter,
            host,
            channel,
            scratch,
            files: 0,
            session_number: 1,
            remote_sequence: 0,
        }
    }

    /// A run of `kind` driven to `stage`.
    fn at(kind: Kind, stage: Stage) -> Self {
        let mut fixture = Self::new(kind);
        if stage >= Stage::Provisioned {
            fixture.provision();
        }
        if stage >= Stage::IdentityEnrolled {
            fixture.enroll();
        }
        if stage >= Stage::RuntimeConfirmed {
            fixture.confirm();
        }
        if stage >= Stage::Running {
            fixture.connect(1).unwrap();
            fixture.launch();
        }
        match stage {
            Stage::AuthorityEnded => fixture.end_authority(),
            Stage::Terminating | Stage::Terminated => fixture
                .adapter
                .begin_termination(&mut fixture.authority)
                .unwrap(),
            _ => {}
        }
        if stage == Stage::Terminated {
            fixture
                .adapter
                .terminate_step(&mut fixture.provider)
                .unwrap();
        }
        assert_eq!(stage_of(fixture.adapter.state()), stage);
        fixture
    }

    /// Replaces the channel with a new one, with its own `known_hosts` file, for `limits`.
    fn reopen(&mut self, limits: SshLimits) {
        self.files += 1;
        let name = format!("known_hosts-{}", self.files);
        self.channel = channel_for(&self.known, self.host, &self.scratch, &name, limits);
    }

    fn provision(&mut self) {
        self.adapter
            .reserve_spend(&self.ledger, &provision_effect(account(), 10_000_000, 1))
            .unwrap();
        let instance = self
            .adapter
            .provision(&mut self.provider, &self.ledger)
            .unwrap();
        assert_eq!(instance.host(), self.host);
    }

    fn enroll(&mut self) {
        let identity = self
            .adapter
            .enroll(&mut self.known, &wire_key(1), provider_api(&wire_key(1)))
            .unwrap();
        assert_eq!(identity.host, self.host);
        assert_eq!(identity.enrollment, self.enrollment().generation);
    }

    /// The host's current enrollment.
    fn enrollment(&self) -> HostEnrollment {
        self.known.enrollment(&self.host).unwrap().clone()
    }

    fn shell(&self) -> ExecutionContext {
        ExecutionContext::RemoteHostShell { host: self.host }
    }

    fn container(&self) -> ExecutionContext {
        ExecutionContext::ProviderContainer { host: self.host }
    }

    fn vm_workload(&self) -> ExecutionContext {
        ExecutionContext::VmWorkload {
            host: self.host,
            vm: vm_id(1),
        }
    }

    /// Confirms the runtime: a dedicated VM from CORE-01 evidence of the instance, a
    /// per-sandbox VM from management evidence of the hardware-accelerated VM workload, a
    /// provider container from CORE-01 evidence, then granted its labelled record.
    fn confirm(&mut self) {
        let instance = self.adapter.instance().unwrap().instance;
        match self.kind {
            Kind::Dedicated => {
                let offer = self
                    .world
                    .remote_offer(instance, ExecutionCategory::VmSandbox);
                self.adapter.confirm_runtime(&offer, None).unwrap();
            }
            Kind::Metal => {
                let evidence = RemoteCapabilityEvidence::observed(
                    &self.enrollment(),
                    self.vm_workload(),
                    RemoteCapability::VmRunning {
                        hardware_accelerated: true,
                    },
                    self.world.now(),
                );
                let offer = self
                    .world
                    .remote_offer(*vm_id(1).digest(), ExecutionCategory::VmSandbox);
                self.adapter
                    .confirm_runtime(&offer, Some(&evidence))
                    .unwrap();
            }
            Kind::Container => {
                let offer = self
                    .world
                    .remote_offer(instance, ExecutionCategory::ProviderContainerRuntime);
                let admitted = self.adapter.confirm_runtime(&offer, None).unwrap();
                self.world
                    .authorize_labelled(pod_execution(), admitted, HOUR)
                    .unwrap();
            }
        }
        assert_eq!(self.adapter.state(), &AdapterState::RuntimeConfirmed);
    }

    // The error type is V12's own; this helper only passes it through.
    #[allow(clippy::result_large_err)]
    fn connect(&mut self, number: u8) -> Result<(), AdapterRefusal> {
        let session = ControlSession::open(
            self.adapter.identity().unwrap().clone(),
            session_id(number),
            session_key(number),
            control_key(number),
            self.world.now(),
        );
        let result = self
            .adapter
            .connect(&self.known, &wire_key(1), session, &mut self.authority);
        if result.is_ok() {
            self.session_number = number;
            self.remote_sequence = 0;
        }
        result
    }

    fn launch(&mut self) {
        self.adapter
            .launch(
                &mut self.authority,
                OperationId::new("op-remote").unwrap(),
                None,
            )
            .unwrap();
        assert_eq!(self.adapter.state(), &AdapterState::Running);
    }

    /// An authenticated heartbeat from the remote, which keeps the control session live.
    fn heartbeat(&mut self) {
        let frame = ControlFrame {
            session: session_id(self.session_number),
            identity: self.adapter.identity().unwrap().digest(),
            sequence: self.remote_sequence,
            body: ControlBody::Heartbeat,
        }
        .seal(&control_key(self.session_number));
        self.remote_sequence += 1;
        assert_eq!(
            self.adapter.handle_frame(&frame, &mut self.authority),
            Ok(FrameOutcome::Heard)
        );
    }

    /// Ends the run's authority as V12 does: a lease left to expire, a labelled record
    /// revoked.
    fn end_authority(&mut self) {
        match self.kind {
            Kind::Dedicated | Kind::Metal => self.world.advance(11 * MINUTE),
            Kind::Container => self.world.revoke_labelled(&pod_execution()),
        }
        assert!(self.adapter.check_authority(&mut self.authority).is_err());
    }

    /// Where the run's kind does `action`: a container its password and logs in the
    /// container, a VM run its password in the VM workload, the rest in the host shell.
    fn context_for(&self, action: ManagementAction) -> ExecutionContext {
        match (self.kind, action) {
            (Kind::Container, ReplaceJupyterPassword | CollectLogs) => self.container(),
            (_, ReplaceJupyterPassword) => self.vm_workload(),
            _ => self.shell(),
        }
    }

    fn invocation(&self, action: ManagementAction) -> RemoteInvocation {
        self.invocation_in(action, self.context_for(action))
    }

    fn invocation_in(
        &self,
        action: ManagementAction,
        context: ExecutionContext,
    ) -> RemoteInvocation {
        invocation(&self.identity, &self.known, action, context)
    }

    fn port(&self) -> &ScriptedPort {
        self.channel.port()
    }

    fn call_as(
        &mut self,
        identity: &ManagementIdentity,
        invocation: &RemoteInvocation,
    ) -> Result<ManagementCall, ManagementCallRefusal> {
        self.channel.call(
            &mut self.adapter,
            &mut self.authority,
            &self.known,
            identity,
            invocation,
        )
    }

    fn probe_as(
        &mut self,
        identity: &ManagementIdentity,
    ) -> Result<ProbeResult, ManagementCallRefusal> {
        self.channel.probe_hardware_virtualization(
            &mut self.adapter,
            &mut self.authority,
            &self.known,
            identity,
        )
    }

    fn probe(&mut self) -> Result<ProbeResult, ManagementCallRefusal> {
        let identity = self.identity.clone();
        self.probe_as(&identity)
    }

    /// Calls `invocation` under `identity` and expects it refused before the port saw it.
    fn refused_as(
        &mut self,
        identity: &ManagementIdentity,
        invocation: &RemoteInvocation,
    ) -> ManagementCallRefusal {
        let before = self.port().calls();
        let refusal = self.call_as(identity, invocation).unwrap_err();
        assert_eq!(self.port().calls(), before, "{refusal:?} reached the port");
        refusal
    }

    fn refused(&mut self, invocation: &RemoteInvocation) -> ManagementCallRefusal {
        let identity = self.identity.clone();
        self.refused_as(&identity, invocation)
    }

    /// Calls `invocation` and expects it rendered, run once and reported under the host's
    /// current enrollment.
    fn ran(&mut self, invocation: &RemoteInvocation) -> ManagementCall {
        let identity = self.identity.clone();
        let before = self.port().calls();
        let call = self.call_as(&identity, invocation).unwrap();
        assert_eq!(self.port().calls(), before + 1);
        let argv = self.port().last_argv();
        assert_eq!(argv.first().map(String::as_str), Some("ssh"));
        assert_eq!(
            argv.last().map(String::as_str),
            Some(invocation.command().as_str())
        );
        assert_eq!(call.action, invocation.action());
        assert_eq!(call.context, invocation.context());
        assert_eq!(call.enrollment, self.enrollment());
        assert_eq!(call.ended_at, self.world.now());
        call
    }
}

/// The actions that run in `stage` for `kind`, as the table on `ManagementChannel::call`
/// has them. A provider container is managed only in its container, where V12 builds the
/// Jupyter password and logs and nothing else.
fn runs(kind: Kind, stage: Stage) -> &'static [ManagementAction] {
    match (kind, stage) {
        (_, Stage::Planned | Stage::Provisioned | Stage::Terminated) => &[],
        (Kind::Metal, Stage::IdentityEnrolled) => {
            &[LaunchVm, SuperviseVm, CollectLogs, TerminateVm]
        }
        (Kind::Dedicated, Stage::IdentityEnrolled) => &[SuperviseVm, CollectLogs, TerminateVm],
        (Kind::Container, Stage::IdentityEnrolled | Stage::AuthorityEnded | Stage::Terminating) => {
            &[CollectLogs]
        }
        (Kind::Container, Stage::RuntimeConfirmed | Stage::Running) => {
            &[ReplaceJupyterPassword, CollectLogs]
        }
        (_, Stage::RuntimeConfirmed | Stage::Running) => &[
            SuperviseVm,
            ReplaceJupyterPassword,
            CollectLogs,
            TerminateVm,
        ],
        (_, Stage::AuthorityEnded | Stage::Terminating) => &[CollectLogs, TerminateVm],
    }
}

#[test]
fn each_call_runs_only_as_the_table_allows_for_each_kind_of_run() {
    for kind in Kind::ALL {
        for stage in Stage::ALL {
            let mut fixture = Fixture::at(kind, stage);
            for action in ManagementAction::ALL {
                let invocation = fixture.invocation(action);
                let case = format!("{kind:?} {stage:?} {action:?}");
                if runs(kind, stage).contains(&action) {
                    let call = fixture.ran(&invocation);
                    assert_eq!(
                        call.run.outcome,
                        SshOutcome::RemoteExit { code: 0 },
                        "{case}"
                    );
                    continue;
                }
                let expected = if stage <= Stage::Provisioned {
                    ManagementCallRefusal::NotEnrolled
                } else if kind == Kind::Container && invocation.context() == fixture.shell() {
                    ManagementCallRefusal::ContextForAnotherKind {
                        context: fixture.shell(),
                    }
                } else {
                    ManagementCallRefusal::NotNow {
                        action,
                        state: fixture.adapter.state().clone(),
                    }
                };
                assert_eq!(fixture.refused(&invocation), expected, "{case}");
            }
            // No call moved the run, and a running one still holds its authority.
            assert_eq!(stage_of(fixture.adapter.state()), stage, "{kind:?}");
        }
    }
}

#[test]
fn a_per_sandbox_vm_is_launched_while_enrolled_and_never_after_confirmation() {
    let mut fixture = Fixture::at(Kind::Metal, Stage::IdentityEnrolled);
    let launch = fixture.invocation(LaunchVm);
    // A launch whose client never connected may be retried before confirmation.
    fixture.port().reply(exited(
        255,
        "ssh: connect to host 203.0.113.7 port 2222: Connection refused\r\n",
    ));
    let failed = fixture.ran(&launch);
    assert_eq!(
        failed.run.outcome,
        SshOutcome::ConnectionFailed {
            failure: ConnectionFailure::Refused
        }
    );
    fixture.ran(&launch);
    fixture.confirm();
    assert_eq!(
        fixture.refused(&launch),
        ManagementCallRefusal::NotNow {
            action: LaunchVm,
            state: AdapterState::RuntimeConfirmed
        }
    );
    fixture.connect(1).unwrap();
    fixture.launch();
    assert_eq!(
        fixture.refused(&launch),
        ManagementCallRefusal::NotNow {
            action: LaunchVm,
            state: AdapterState::Running
        }
    );

    // A dedicated VM is the provider's own VM: management never launches it.
    let mut fixture = Fixture::at(Kind::Dedicated, Stage::IdentityEnrolled);
    let launch = fixture.invocation(LaunchVm);
    assert_eq!(
        fixture.refused(&launch),
        ManagementCallRefusal::NotNow {
            action: LaunchVm,
            state: AdapterState::IdentityEnrolled
        }
    );
}

#[test]
fn expired_authority_ends_at_the_next_supervise_and_no_reconnect_revives_it() {
    let mut fixture = Fixture::at(Kind::Dedicated, Stage::Running);
    let supervise = fixture.invocation(SuperviseVm);
    let password = fixture.invocation(ReplaceJupyterPassword);
    let logs = fixture.invocation(CollectLogs);
    let terminate = fixture.invocation(TerminateVm);
    fixture.ran(&supervise);
    // Past the ten-minute term, never renewed.
    fixture.world.advance(11 * MINUTE);
    let refusal = fixture.refused(&supervise);
    assert!(
        matches!(
            authority_refusal(&refusal),
            Some(AdapterRefusal::Authority {
                refusal: LifetimeRefusal::Lease {
                    refusal: LeaseRefusal::Expired { .. }
                }
            })
        ),
        "{refusal:?}"
    );
    assert!(matches!(
        fixture.adapter.state(),
        AdapterState::AuthorityEnded {
            reason: AuthorityEnd::LeaseRefused { .. }
        }
    ));
    assert!(fixture
        .adapter
        .acknowledgments()
        .contains_key(&RevocationMilestone::NewAuthorizationsDenied));
    let ended = fixture.adapter.state().clone();
    let not_now = |action| ManagementCallRefusal::NotNow {
        action,
        state: ended.clone(),
    };
    assert_eq!(fixture.refused(&supervise), not_now(SuperviseVm));
    assert_eq!(fixture.refused(&password), not_now(ReplaceJupyterPassword));
    fixture.ran(&logs);
    fixture.ran(&terminate);
    // A reconnect is refused and changes nothing.
    assert_eq!(
        fixture.connect(2),
        Err(AdapterRefusal::InvalidStep {
            state: ended.clone(),
            step: AdapterStep::Connect
        })
    );
    assert_eq!(fixture.adapter.state(), &ended);
    assert_eq!(fixture.refused(&supervise), not_now(SuperviseVm));
    fixture.ran(&logs);

    // When the reconnect comes first, it finds the expiry and ends authority itself.
    let mut fixture = Fixture::at(Kind::Metal, Stage::Running);
    let supervise = fixture.invocation(SuperviseVm);
    let logs = fixture.invocation(CollectLogs);
    fixture.adapter.connection_lost();
    fixture.world.advance(11 * MINUTE);
    assert!(matches!(
        fixture.connect(2),
        Err(AdapterRefusal::Authority {
            refusal: LifetimeRefusal::Lease {
                refusal: LeaseRefusal::Expired { .. }
            }
        })
    ));
    assert!(matches!(
        fixture.refused(&supervise),
        ManagementCallRefusal::NotNow {
            action: SuperviseVm,
            state: AdapterState::AuthorityEnded { .. }
        }
    ));
    fixture.ran(&logs);
}

#[test]
fn a_call_that_could_outlast_the_lease_is_not_started_until_it_is_renewed() {
    let mut fixture = Fixture::at(Kind::Dedicated, Stage::Running);
    let deadline = Duration::from_secs(60);
    fixture.reopen(SshLimits::new(10, 10, 2, deadline, 256 * 1024, 256 * 1024).unwrap());
    let supervise = fixture.invocation(SuperviseVm);
    let password = fixture.invocation(ReplaceJupyterPassword);
    let logs = fixture.invocation(CollectLogs);
    let expires_at = fixture.adapter.lease().unwrap().expires_at();
    // Nine minutes into the ten-minute lease, a 60 s call ends at the expiry: it runs.
    fixture.world.advance(9 * MINUTE);
    fixture.ran(&supervise);
    // With 9.5 minutes used it could outlast the lease, so it is not started.
    fixture.world.advance(30 * SECOND);
    let ends_first = ManagementCallRefusal::AuthorityEndsFirst {
        expires_at,
        deadline_at: fixture.world.now().saturating_add(deadline),
    };
    assert_eq!(fixture.refused(&supervise), ends_first);
    assert_eq!(fixture.refused(&password), ends_first);
    assert_eq!(fixture.adapter.state(), &AdapterState::Running);
    // Logs need no authority.
    fixture.ran(&logs);
    // The remote is heard from, the host renews, and the call runs.
    fixture.heartbeat();
    fixture.adapter.renew(&mut fixture.authority).unwrap();
    assert!(fixture.adapter.lease().unwrap().expires_at() > expires_at);
    fixture.ran(&supervise);
    fixture.ran(&password);
}

#[test]
fn a_changed_host_key_closes_the_channel_and_stops_renewals() {
    let mut fixture = Fixture::at(Kind::Dedicated, Stage::Running);
    let supervise = fixture.invocation(SuperviseVm);
    // Built before the mismatch: afterwards no invocation is built for the enrollment.
    let invocations: Vec<RemoteInvocation> = ManagementAction::ALL
        .iter()
        .map(|&action| fixture.invocation(action))
        .collect();
    let enrollment = fixture.enrollment();
    let enrolled = wire_key(1).fingerprint();
    fixture.port().reply(exited(255, HOST_KEY_FAILED));
    let identity = fixture.identity.clone();
    let call = fixture.call_as(&identity, &supervise).unwrap();
    assert_eq!(fixture.port().calls(), 1);
    assert_eq!(call.enrollment, enrollment);
    assert_eq!(
        call.run.outcome,
        SshOutcome::HostKeyMismatch {
            host: fixture.host,
            enrolled,
            evidence: HostKeyEvidence::Unverified
        }
    );
    assert_eq!(call.command_ran(), None);
    assert_eq!(
        fixture.channel.rejected(),
        Some(&RejectedHostKey {
            host: fixture.host,
            enrolled,
            evidence: HostKeyEvidence::Unverified
        })
    );
    // The rejection is recorded against the enrollment and authority ended at once, so
    // nothing is renewed.
    assert!(matches!(
        fixture.adapter.state(),
        AdapterState::AuthorityEnded {
            reason: AuthorityEnd::HostKeyRejected { .. }
        }
    ));
    assert!(fixture
        .known
        .rejection(&fixture.host, enrollment.generation)
        .is_some());
    assert!(matches!(
        fixture.adapter.renew(&mut fixture.authority),
        Err(AdapterRefusal::InvalidStep { .. })
    ));
    // No later call runs, terminate and the probe included.
    let rejected = ManagementCallRefusal::HostKeyRejected {
        host: fixture.host,
        enrolled,
    };
    for invocation in &invocations {
        assert_eq!(
            fixture.refused(invocation),
            rejected,
            "{:?}",
            invocation.action()
        );
    }
    assert_eq!(fixture.probe().unwrap_err(), rejected);
    // No `known_hosts` file is rendered for the rejected enrollment again, so no other
    // channel opens for it.
    let target = SshTarget::new(fixture.host, authority(ADDRESS));
    assert!(EnrolledHostKey::new(
        &fixture.known,
        target,
        HostKeyAlgorithm::Ed25519,
        ed25519_blob(1)
    )
    .is_err());
    assert_eq!(fixture.port().calls(), 1);
}

#[test]
fn a_call_for_another_enrolled_host_is_refused() {
    let mut fixture = Fixture::at(Kind::Dedicated, Stage::Running);
    let other = fixture.other.clone();
    let identity = fixture.identity.clone();
    let elsewhere = invocation(
        &other,
        &fixture.known,
        CollectLogs,
        ExecutionContext::RemoteHostShell { host: other.host() },
    );
    let here = fixture.invocation(CollectLogs);
    let wrong = ManagementCallRefusal::WrongHost {
        run: fixture.host,
        other: other.host(),
    };
    // The other host's identity, with its own invocation or with one for the run's host.
    assert_eq!(fixture.refused_as(&other, &elsewhere), wrong);
    assert_eq!(fixture.refused_as(&other, &here), wrong);
    assert_eq!(fixture.probe_as(&other).unwrap_err(), wrong);
    // The run's identity with an invocation for the other host.
    assert_eq!(fixture.refused_as(&identity, &elsewhere), wrong);
    assert_eq!(fixture.port().calls(), 0);
    fixture.ran(&here);
}

#[test]
fn a_host_re_enrolled_outside_the_adapter_is_a_stale_identity() {
    // Retired only; re-enrolled with the same key under a new generation; with another key.
    for seed in [None, Some(1), Some(3)] {
        let mut fixture = Fixture::at(Kind::Dedicated, Stage::Running);
        let mut invocations = vec![
            fixture.invocation(SuperviseVm),
            fixture.invocation(CollectLogs),
            fixture.invocation(TerminateVm),
        ];
        let host = fixture.host;
        fixture.known.retire(&host);
        if let Some(seed) = seed {
            let enrollment = fixture
                .known
                .enroll(
                    host,
                    &wire_key(seed),
                    provider_api(&wire_key(seed)),
                    EnrollmentPolicy::default(),
                    fixture.world.now(),
                )
                .unwrap();
            assert!(enrollment.generation > fixture.adapter.identity().unwrap().enrollment);
            // A management identity for the new enrollment, and its own invocations.
            fixture.identity = identity_for(&enrollment, &ManagementAction::ALL);
            invocations.push(fixture.invocation(SuperviseVm));
            invocations.push(fixture.invocation(TerminateVm));
        }
        for invocation in &invocations {
            assert_eq!(
                fixture.refused(invocation),
                ManagementCallRefusal::StaleIdentity,
                "{seed:?}"
            );
        }
        assert_eq!(
            fixture.probe().unwrap_err(),
            ManagementCallRefusal::StaleIdentity
        );
        assert_eq!(fixture.port().calls(), 0);
        assert_eq!(fixture.adapter.state(), &AdapterState::Running);
    }
}

#[test]
fn a_context_foreign_to_the_kind_of_run_is_refused() {
    // A provider-container context on a VM run.
    for kind in [Kind::Dedicated, Kind::Metal] {
        let mut fixture = Fixture::at(kind, Stage::Running);
        let container = fixture.container();
        for action in [ReplaceJupyterPassword, CollectLogs] {
            let invocation = fixture.invocation_in(action, container);
            assert_eq!(
                fixture.refused(&invocation),
                ManagementCallRefusal::ContextForAnotherKind { context: container },
                "{kind:?} {action:?}"
            );
        }
        assert_eq!(fixture.port().calls(), 0);
    }
    // A host-shell or VM-workload context on a container run.
    let mut fixture = Fixture::at(Kind::Container, Stage::Running);
    let shell = fixture.shell();
    let workload = fixture.vm_workload();
    for (action, context) in [
        (LaunchVm, shell),
        (SuperviseVm, shell),
        (TerminateVm, shell),
        (CollectLogs, shell),
        (CollectLogs, workload),
        (ReplaceJupyterPassword, workload),
    ] {
        let invocation = fixture.invocation_in(action, context);
        assert_eq!(
            fixture.refused(&invocation),
            ManagementCallRefusal::ContextForAnotherKind { context },
            "{action:?}"
        );
    }
    assert_eq!(
        fixture.probe().unwrap_err(),
        ManagementCallRefusal::ContextForAnotherKind { context: shell }
    );
    assert_eq!(fixture.port().calls(), 0);
    assert_eq!(fixture.adapter.state(), &AdapterState::Running);
}

#[test]
fn a_provider_container_gets_its_password_only_within_its_labelled_grant() {
    let mut fixture = Fixture::at(Kind::Container, Stage::Running);
    assert!(matches!(
        fixture.adapter.delegation(),
        Some(Delegation::Labelled { .. })
    ));
    let password = fixture.invocation(ReplaceJupyterPassword);
    let logs = fixture.invocation(CollectLogs);
    let call = fixture.ran(&password);
    assert_eq!(call.context, fixture.container());
    // The password went over stdin as one line, and into no argv word.
    let mut line = PASSWORD.to_vec();
    line.push(b'\n');
    assert_eq!(fixture.port().last_stdin(), Some(line));
    let secret = std::str::from_utf8(PASSWORD).unwrap();
    assert!(fixture
        .port()
        .last_argv()
        .iter()
        .all(|word| !word.contains(secret)));
    // The host revokes the labelled record: the next password call ends the run's authority.
    fixture.world.revoke_labelled(&pod_execution());
    let refusal = fixture.refused(&password);
    assert!(
        matches!(
            authority_refusal(&refusal),
            Some(AdapterRefusal::Labelled {
                refusal: LeaseRefusal::RevokedAuthorization { .. }
            })
        ),
        "{refusal:?}"
    );
    assert!(matches!(
        fixture.adapter.state(),
        AdapterState::AuthorityEnded {
            reason: AuthorityEnd::LabelledRefused { .. }
        }
    ));
    assert!(matches!(
        fixture.refused(&password),
        ManagementCallRefusal::NotNow {
            action: ReplaceJupyterPassword,
            state: AdapterState::AuthorityEnded { .. }
        }
    ));
    fixture.ran(&logs);

    // Within the grant also means ending within it: a minute before the grant expires, a
    // call with the standard 120 s deadline is not started.
    let mut fixture = Fixture::at(Kind::Container, Stage::Running);
    let password = fixture.invocation(ReplaceJupyterPassword);
    let logs = fixture.invocation(CollectLogs);
    let expires_at = fixture.adapter.delegation().unwrap().expires_at();
    fixture.world.advance(59 * MINUTE);
    assert_eq!(
        fixture.refused(&password),
        ManagementCallRefusal::AuthorityEndsFirst {
            expires_at,
            deadline_at: fixture
                .world
                .now()
                .saturating_add(SshLimits::STANDARD.deadline()),
        }
    );
    assert_eq!(fixture.adapter.state(), &AdapterState::Running);
    fixture.ran(&logs);
}

#[test]
fn the_kvm_probe_gives_host_shell_evidence_that_never_confirms_a_per_sandbox_vm() {
    let mut fixture = Fixture::at(Kind::Metal, Stage::IdentityEnrolled);
    let enrollment = fixture.enrollment();
    let shell = fixture.shell();
    let encoded = format!("'{TEST_PROGRAM}' '-c' '{KVM_DEVICE}'");
    for (code, available) in [(0, Some(true)), (1, Some(false)), (2, None)] {
        fixture.port().reply(exited(code, ""));
        let probe = fixture.probe().unwrap();
        assert_eq!(fixture.port().last_argv().last(), Some(&encoded));
        assert_eq!(probe.call.action, SuperviseVm);
        assert_eq!(probe.call.context, shell);
        assert_eq!(probe.call.enrollment, enrollment);
        assert_eq!(
            probe.call.run.outcome,
            SshOutcome::RemoteExit {
                code: u8::try_from(code).unwrap()
            }
        );
        let now = fixture.world.now();
        assert_eq!(
            probe.evidence,
            available.map(|available| RemoteCapabilityEvidence::observed(
                &enrollment,
                shell,
                RemoteCapability::HardwareVirtualization { available },
                now
            ))
        );
        let ran = probe.call.command_ran().unwrap();
        assert_eq!(
            ran,
            RemoteCapabilityEvidence::observed(
                &enrollment,
                shell,
                RemoteCapability::ShellCommand,
                now
            )
        );
        let host_shell = RemoteEvidenceRefusal::HostShellIsNotTheSandbox {
            predicate: SecurityPredicate::VmSandbox,
        };
        for evidence in probe.evidence.iter().chain([&ran]) {
            // The host shell, under the host's current (second) enrollment generation.
            assert_eq!(evidence.context, shell);
            assert_eq!(evidence.enrollment, enrollment.generation);
            assert_eq!(evidence.assumptions, enrollment.assumptions);
            assert_eq!(
                evidence.supports(SecurityPredicate::VmSandbox),
                Err(host_shell.clone())
            );
            // V12 refuses it to confirm the per-sandbox VM, and the run stays enrolled.
            let offer = fixture
                .world
                .remote_offer(*vm_id(1).digest(), ExecutionCategory::VmSandbox);
            assert_eq!(
                fixture.adapter.confirm_runtime(&offer, Some(evidence)),
                Err(AdapterRefusal::ManagementEvidence {
                    refusal: host_shell.clone()
                })
            );
            assert_eq!(fixture.adapter.state(), &AdapterState::IdentityEnrolled);
        }
        fixture.world.advance(SECOND);
    }
    // A host-key mismatch gives no evidence, not even that a command ran.
    fixture.port().reply(exited(255, HOST_KEY_FAILED));
    let probe = fixture.probe().unwrap();
    assert_eq!(fixture.port().last_argv().last(), Some(&encoded));
    assert!(matches!(
        probe.call.run.outcome,
        SshOutcome::HostKeyMismatch { .. }
    ));
    assert_eq!(probe.evidence, None);
    assert_eq!(probe.call.command_ran(), None);
    assert!(fixture.channel.rejected().is_some());
    assert_eq!(fixture.port().calls(), 4);
}

#[test]
fn refusals_are_tagged_by_kind() {
    let mut fixture = Fixture::at(Kind::Dedicated, Stage::AuthorityEnded);
    let supervise = fixture.invocation(SuperviseVm);
    let refusal = fixture.refused(&supervise);
    let json = serde_json::to_value(&refusal).unwrap();
    assert_eq!(json["kind"], "not_now");
    assert_eq!(json["action"], "supervise_vm");
    assert_eq!(json["state"]["state"], "authority_ended");
    assert!(refusal.to_string().contains("SuperviseVm"));
    let authority = ManagementCallRefusal::Authority {
        refusal: Box::new(AdapterRefusal::NoControlSession),
    };
    assert_eq!(
        serde_json::to_value(&authority).unwrap(),
        serde_json::json!({"kind": "authority", "refusal": {"kind": "no_control_session"}})
    );
    assert_eq!(
        authority.to_string(),
        AdapterRefusal::NoControlSession.to_string()
    );
}
