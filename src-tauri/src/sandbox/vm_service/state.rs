//! The service's state behind its mutex and the transport driver of each boot (module
//! docs in `mod.rs`).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::foundation::coordination::{
    LeaseId, LeaseKind, LedgerCapacity, ReservationPriority, ResourceKind, SandboxLifecycle,
    SandboxState, SettingsGrant, VmInstanceId,
};
use crate::foundation::evidence::{
    AdmittedRuntime, Capability, RuntimeOffer, RuntimeRequirement, Subject,
};
use crate::foundation::ids::{
    Clock, ExecutionCategory, ExecutionId, MonotonicTime, OperationId, SandboxBootGeneration,
    TrustScope,
};
use crate::foundation::process::{ProcessIdentity, ProcessRole};
use crate::sandbox::backend::VmBackend as _;
use crate::sandbox::backend::{
    check_endpoints, GuestEgressEndpoint, NetworkAuthority, NetworkChannel,
};
use crate::sandbox::guest_files::{channel_limits, BodyTransfers, FilesLimits};
use crate::sandbox::host::{
    BootSession, ChannelSetup, CommandEvent, CommandRequest, CommandResult, Delivery,
    EgressEndCause, EgressEvent, EgressRefusal, HostError, HostShutdown, IngressEvent, PumpEvent,
    SandboxHost, SessionPump,
};
use crate::sandbox::integration::LaunchProfile;
use crate::sandbox::lifecycle::{
    Acknowledgment, ActivityKind, CallTerms, CleanupReport, LaunchReceipt, LaunchRequest,
    LeaseLimits, LogicalCleanupAction, ObservedReadiness, RevocationCause, RevocationRun,
    SandboxClass, SandboxRecord,
};
use crate::sandbox::link::GrantHandle;
use crate::sandbox::link::{
    CloseCause, ConnectionNonce, HostLink, LinkLimits, LinkName, LinkPhase, StreamId,
};
use crate::sandbox::link_transport::{
    DriverCounters, DriverLimits, DriverPhase, EndpointRefusal, LinkConnector, LinkSocketEndpoint,
    StreamShutdown, TransportEnd, TransportEvent,
};
use crate::sandbox::qemu::{PrivateDirectory, TerminationEvidence};
use crate::sandbox_contract::file_protocol::FileDispatcher;
use crate::sandbox_contract::files::{
    FileGrant, FileOperation, FileQuota, FileService, GrantMode, GrantedRoot,
};

use super::config::{EvidenceSubjects, PinnedImage, VmServiceConfig};
use super::dto::{
    BootPhase, ChannelsClosedOnShutdown, CommandId, DirectoryRemoval, ExecEnd, ExecOutcome,
    ExecRequest, GuestShutdownOutcome, LaunchRecordView, LaunchSpec, LinkView, Milestone,
    ReadinessBy, ReadinessView, RevocationReport, RevocationView, RevokeReason, SandboxId,
    SandboxStatus, ShutdownNotRequested, ShutdownReport, TransportView, VmStop, TERMINAL_COLUMNS,
    TERMINAL_ROWS,
};
use super::egress::{EgressInbound, EgressPort, EgressView};
use super::error::{EvidenceStep, HostRefusal, LaunchCleanup, LaunchStep, VmServiceError};
use super::ingress::{
    end_detail, refusal_detail, GuestIngress, IngressShared, IngressView, RequestStep,
};
use super::ports::{ServiceLedger, VmPorts};
use super::ServiceRuntime;

/// The most ended commands a boot keeps for callers that have not taken their outcome;
/// the oldest goes first.
pub(super) const MAX_UNCLAIMED_OUTCOMES: usize = 64;

/// Acceptance builds only: when set, the next launch asks for a GPU (VM-CP-33's
/// `cp33.gpu-path-unavailable`): a backend without a GPU path must refuse it by name, never
/// start it without the GPU.
#[cfg(feature = "acceptance")]
pub static PLANT_GPU_REQUEST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "acceptance")]
fn plant_gpu_request(profile: &mut LaunchProfile) {
    if !PLANT_GPU_REQUEST.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let planted = crate::foundation::ids::digest("yougori/acceptance/planted-gpu/v1", &[b"gpu0"]);
    profile
        .device_profile
        .devices
        .gpus
        .insert(crate::foundation::ids::GpuDeviceKey {
            machine: planted,
            device: planted,
        });
}

/// How many refused launches the service keeps for its callers.
const MAX_KEPT_REFUSALS: usize = 32;

/// The grant a sandbox's staged workspace is served on; the guest agent mounts it at
/// `/run/yougori/workspace` (appliance/agent `workspace_linux.go`).
pub const WORKSPACE_GRANT: GrantHandle = GrantHandle(1);

/// What the guest may do in its staged workspace: everything, since nothing reaches the
/// user's folder before a reviewed promotion.
const WORKSPACE_OPERATIONS: [FileOperation; 7] = [
    FileOperation::Read,
    FileOperation::List,
    FileOperation::Create,
    FileOperation::Write,
    FileOperation::Delete,
    FileOperation::Rename,
    FileOperation::SetExecutable,
];

/// The terms of the one authorization a revocation asks for to observe its denial.
const PROBE_CALL: CallTerms = CallTerms {
    per_call: Duration::from_secs(1),
    task: Duration::from_secs(1),
};

type ResolverOf<P> = <<P as VmPorts>::Ledger as ServiceLedger<<P as VmPorts>::Clock>>::Resolver;
pub(super) type StreamOf<P> = <<P as VmPorts>::Connector as LinkConnector>::Stream;

/// The QEMU backend over the service's three host ports and the ledger's view.
pub(super) type ServiceBackend<P> = <P as VmPorts>::Backend;

/// The sandbox host the service owns.
pub(super) type ServiceHost<P> = SandboxHost<
    <P as VmPorts>::Clock,
    LedgerCapacity<<P as VmPorts>::Clock, <P as VmPorts>::Ledger>,
    ServiceBackend<P>,
    ResolverOf<P>,
    <P as VmPorts>::Segments,
    <P as VmPorts>::Spool,
    <P as VmPorts>::Anchor,
>;

/// The service's state and the condition its waiting calls wait on.
pub(super) struct Shared<P: VmPorts> {
    core: Mutex<Core<P>>,
    changed: Condvar,
}

impl<P: VmPorts> Shared<P> {
    pub(super) fn new(core: Core<P>) -> Self {
        Self {
            core: Mutex::new(core),
            changed: Condvar::new(),
        }
    }

    /// The state, locked. A thread that panicked while holding it left it as it was; the
    /// host's own invariants hold between its calls, so the state is used as it stands.
    pub(super) fn lock(&self) -> MutexGuard<'_, Core<P>> {
        self.core.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Releases `guard` until something changed or `slice` passed, and locks again.
    pub(super) fn wait<'a>(
        &self,
        guard: MutexGuard<'a, Core<P>>,
        slice: Duration,
    ) -> MutexGuard<'a, Core<P>> {
        match self.changed.wait_timeout(guard, slice) {
            Ok((guard, _)) => guard,
            Err(poisoned) => poisoned.into_inner().0,
        }
    }

    /// Wakes every waiting call.
    pub(super) fn notify(&self) {
        self.changed.notify_all();
    }
}

/// What the service keeps of its settings.
pub(super) struct Settings {
    pub(super) image: PinnedImage,
    pub(super) profile: LaunchProfile,
    pub(super) evidence: EvidenceSubjects,
    pub(super) runtime_evidence_max_age: Duration,
    pub(super) limits: DriverLimits,
    pub(super) poll_interval: Duration,
    pub(super) tick_interval: Duration,
    pub(super) wait_slice: Duration,
    pub(super) join_bound: Duration,
    pub(super) shutdown_grace: Duration,
    pub(super) evidence_refresh_interval: Duration,
    pub(super) transfers: BodyTransfers,
}

impl Settings {
    pub(super) fn new(
        config: &VmServiceConfig,
        backend_artifact: crate::foundation::ids::Digest,
        transfers: BodyTransfers,
    ) -> Self {
        Self {
            image: config.image,
            profile: LaunchProfile {
                configuration: config.image.configuration,
                contract: config.contract,
                pinned: crate::sandbox::backend::PinnedArtifacts {
                    guest_image: config.image.guest_image,
                    backend: backend_artifact,
                },
                device_profile: config.device_profile.clone(),
                required: config.required.clone(),
            },
            evidence: config.evidence.clone(),
            runtime_evidence_max_age: config.supervisor.runtime_evidence_max_age,
            limits: config.driver.limits,
            poll_interval: config.driver.poll_interval,
            tick_interval: config.driver.tick_interval,
            wait_slice: config.driver.wait_slice,
            join_bound: config.driver.join_bound,
            shutdown_grace: config.driver.shutdown_grace,
            evidence_refresh_interval: config.driver.evidence_refresh_interval,
            transfers,
        }
    }
}

/// How a boot's ending was observed, once its VM was recorded stopped.
#[derive(Clone, Debug)]
pub(super) struct Ending {
    pub(super) vm_stop: VmStop,
    pub(super) directory: DirectoryRemoval,
}

/// One sandbox's boot, as the service carries it.
pub(super) struct Boot<S: Read + Write + StreamShutdown> {
    pub(super) phase: BootPhase,
    pub(super) boot: SandboxBootGeneration,
    pub(super) vm: Option<VmInstanceId>,
    pub(super) process: Option<ProcessIdentity>,
    pub(super) directory: Option<PrivateDirectory>,
    /// The session pump over the checked link stream, while the driver carries it.
    pub(super) pump: Option<SessionPump<S>>,
    pub(super) counters: DriverCounters,
    pub(super) transport_end: Option<TransportEnd>,
    pub(super) link_closed: Option<CloseCause>,
    /// Running commands, by stream number, with their CORE-04 lease.
    pub(super) running: BTreeMap<u32, LeaseId>,
    /// Ended commands no caller has taken yet.
    pub(super) outcomes: BTreeMap<u32, ExecOutcome>,
    /// Commands a closure of the boot's channels ended and no report has listed yet.
    pub(super) ended_by_closure: Vec<CommandId>,
    pub(super) first_command: bool,
    pub(super) driver: Option<JoinHandle<()>>,
    pub(super) ending: Option<Ending>,
    pub(super) torn_down: bool,
    /// Where the guest's egress streams go while a port is attached.
    pub(super) egress_port: Option<Box<dyn EgressPort>>,
    /// Callers' ingress streams not opened on the link yet (M14), and those opened, by
    /// stream number, each with the buffer it shares with its handle.
    pub(super) ingress_requests: Vec<Arc<IngressShared>>,
    pub(super) ingress: BTreeMap<u32, Arc<IngressShared>>,
    /// The boot's sandbox connection endpoints (M14), and the egress streams its programs
    /// opened to them, by stream number, each with the buffer the gate's handle shares.
    pub(super) connection_names: BTreeSet<LinkName>,
    pub(super) connections: BTreeMap<u32, Arc<IngressShared>>,
    /// Ingress streams opened on the link since the launch: each one asked the guest to open
    /// a port of its service (a drill counts them).
    pub(super) ingress_opened: u64,
    /// Remote-controlled boots retain their gate after closure, so local command
    /// entrypoints cannot silently become an authority bypass after disconnect.
    pub(super) remote: Option<super::remote::RemoteControl>,
}

impl<S: Read + Write + StreamShutdown> Boot<S> {
    fn new(
        boot: SandboxBootGeneration,
        vm: Option<VmInstanceId>,
        process: Option<ProcessIdentity>,
        directory: Option<PrivateDirectory>,
    ) -> Self {
        Self {
            phase: BootPhase::Starting,
            boot,
            vm,
            process,
            directory,
            pump: None,
            counters: DriverCounters::default(),
            transport_end: None,
            link_closed: None,
            running: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            ended_by_closure: Vec::new(),
            first_command: false,
            driver: None,
            ending: None,
            torn_down: false,
            egress_port: None,
            ingress_requests: Vec::new(),
            ingress: BTreeMap::new(),
            connection_names: BTreeSet::new(),
            connections: BTreeMap::new(),
            ingress_opened: 0,
            remote: None,
        }
    }
}

/// What a driver does after one pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DriverPass {
    /// Something moved: pass again at once.
    Busy,
    /// Nothing moved: sleep the poll interval first.
    Idle,
    /// The boot's pump finished or the service shuts down.
    Stop,
}

/// Which pump call to make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PumpCall {
    Step,
    Flush,
}

/// Where a launch's handshake stands.
pub(super) enum Hello {
    Open,
    Waiting,
    Failed(LaunchStep),
}

/// Leases to give back and first commands to mark, collected while the boots are
/// borrowed.
#[derive(Default)]
struct Taken {
    leases: Vec<LeaseId>,
    first_commands: Vec<ExecutionId>,
    /// Egress streams whose port refused, to cancel on the link.
    egress_cancels: Vec<(ExecutionId, StreamId)>,
    /// Ingress streams whose caller closed or does not take the guest's bytes.
    ingress_cancels: Vec<(ExecutionId, StreamId)>,
    /// Ingress bytes callers took (or that a closed caller will never take): credit due to
    /// each stream.
    ingress_credit: Vec<(ExecutionId, StreamId, u64)>,
    /// Streams a guest's program opened to a connection endpoint, for the gate (M14).
    connection_opens: Vec<(ExecutionId, StreamId, LinkName, Arc<IngressShared>)>,
}

/// Hands one egress event to the boot's port; a port that refuses has the stream cancelled.
/// A sandbox connection's stream is the gate's, never the port's.
fn forward_egress<S: Read + Write + StreamShutdown>(
    boot: &mut Boot<S>,
    sandbox: &ExecutionId,
    event: EgressEvent,
    taken: &mut Taken,
) {
    if forward_connection(boot, sandbox, &event, taken) {
        return;
    }
    let Some(port) = boot.egress_port.as_mut() else {
        return;
    };
    match event {
        EgressEvent::Opened {
            stream,
            destination,
        } => {
            if port.opened(stream, &destination).is_err() {
                taken.egress_cancels.push((sandbox.clone(), stream));
            }
        }
        EgressEvent::Data { stream, bytes } => {
            if port.data(stream, &bytes).is_err() {
                taken.egress_cancels.push((sandbox.clone(), stream));
            }
        }
        EgressEvent::GuestEnded { stream } => port.guest_ended(stream),
        EgressEvent::Ended { stream, .. } => port.ended(stream),
        EgressEvent::Refused { .. } => {}
    }
}

/// Takes `event` when it is of a sandbox connection's stream (M14; module docs in `connect`):
/// an open to a connection endpoint gets a buffer and waits for the gate; the stream's bytes
/// and ends go to its buffer. Whether the event was one.
fn forward_connection<S: Read + Write + StreamShutdown>(
    boot: &mut Boot<S>,
    sandbox: &ExecutionId,
    event: &EgressEvent,
    taken: &mut Taken,
) -> bool {
    match event {
        EgressEvent::Opened {
            stream,
            destination,
        } if boot.connection_names.contains(destination) => {
            let shared = IngressShared::accepted(*stream, destination.clone());
            boot.connections.insert(stream.get(), Arc::clone(&shared));
            taken
                .connection_opens
                .push((sandbox.clone(), *stream, destination.clone(), shared));
            true
        }
        EgressEvent::Data { stream, bytes } => match boot.connections.get(&stream.get()) {
            Some(shared) => {
                if !shared.received(bytes) {
                    shared.ended("the connection did not take the guest's bytes".to_owned());
                    taken.egress_cancels.push((sandbox.clone(), *stream));
                }
                true
            }
            None => false,
        },
        EgressEvent::GuestEnded { stream } => match boot.connections.get(&stream.get()) {
            Some(shared) => {
                shared.guest_ended();
                true
            }
            None => false,
        },
        EgressEvent::Ended { stream, cause } => match boot.connections.remove(&stream.get()) {
            Some(shared) => {
                shared.ended(egress_end_detail(cause));
                // The stream's window went with it: nothing is credited for what it held.
                shared.release_credit();
                true
            }
            None => false,
        },
        EgressEvent::Opened { .. } | EgressEvent::Refused { .. } => false,
    }
}

/// Why the link ended an egress stream, in words.
fn egress_end_detail(cause: &EgressEndCause) -> String {
    match cause {
        EgressEndCause::Finished => "the stream finished".to_owned(),
        EgressEndCause::GuestCancelled { cancel } => {
            format!("the guest cancelled the stream ({cancel:?})")
        }
        EgressEndCause::HostCancelled => "the host cancelled the stream".to_owned(),
        EgressEndCause::LinkClosed { close } => format!("the link closed ({close:?})"),
        EgressEndCause::HostClosed { closure } => {
            format!("the host closed the sandbox's channels ({closure:?})")
        }
    }
}

/// The endpoints the guest learns at boot: the relay's routes, then the connection endpoints
/// (M14), at most `MAX_GUEST_EGRESS_ENDPOINTS` together and no name twice.
fn launch_endpoints(spec: &LaunchSpec) -> Result<Vec<GuestEgressEndpoint>, String> {
    let mut endpoints = spec.egress_endpoints.clone();
    for endpoint in &spec.connect {
        endpoints.push(endpoint.guest_endpoint()?);
    }
    check_endpoints(&endpoints).map_err(|error| error.to_string())?;
    Ok(endpoints)
}

/// Hands one ingress event to its stream's buffer; a stream whose caller does not take the
/// guest's bytes is cancelled.
fn forward_ingress<S: Read + Write + StreamShutdown>(
    boot: &mut Boot<S>,
    sandbox: &ExecutionId,
    event: IngressEvent,
    taken: &mut Taken,
) {
    match event {
        IngressEvent::Opened { stream } => {
            if let Some(shared) = boot.ingress.get(&stream.get()) {
                shared.opened();
            }
        }
        IngressEvent::Refused { stream, cause } => {
            if let Some(shared) = boot.ingress.remove(&stream.get()) {
                shared.ended(refusal_detail(cause));
                shared.release_credit();
            }
        }
        IngressEvent::Data { stream, bytes } => {
            if let Some(shared) = boot.ingress.get(&stream.get()) {
                if !shared.received(&bytes) {
                    shared.ended("the caller did not take the guest's bytes".to_owned());
                    taken.ingress_cancels.push((sandbox.clone(), stream));
                }
            }
        }
        IngressEvent::GuestEnded { stream } => {
            if let Some(shared) = boot.ingress.get(&stream.get()) {
                shared.guest_ended();
            }
        }
        IngressEvent::Ended { stream, cause } => {
            if let Some(shared) = boot.ingress.remove(&stream.get()) {
                shared.ended(end_detail(&cause));
                // The stream's window went with it: nothing is credited for what it held.
                shared.release_credit();
            }
        }
    }
}

/// Ends every request of `boot` that never opened: its channels are gone.
fn end_ingress_requests<S: Read + Write + StreamShutdown>(boot: &mut Boot<S>, detail: &str) {
    for shared in boot.ingress_requests.drain(..) {
        shared.ended(detail.to_owned());
    }
}

/// The most of a caller's bytes one driver pass hands to one ingress stream.
const INGRESS_CHUNK_BYTES: usize = 256 << 10;

/// The most ingress streams one sandbox holds, requested or open (the guest agent's bound).
pub(super) const MAX_INGRESS_STREAMS: usize = 128;

/// A sandbox's revocation, taken as far as it goes now.
pub(super) struct Ended {
    pub(super) vm_stop: VmStop,
    pub(super) directory: DirectoryRemoval,
    pub(super) commands_ended: Vec<CommandId>,
}

/// The state behind the service's mutex.
pub(super) struct Core<P: VmPorts> {
    /// `None` once the service shut down.
    pub(super) host: Option<ServiceHost<P>>,
    pub(super) boots: BTreeMap<ExecutionId, Boot<StreamOf<P>>>,
    pub(super) connector: P::Connector,
    pub(super) processes: P::Processes,
    pub(super) settings: Settings,
    pub(super) last_tick: Option<MonotonicTime>,
    /// When the host's probe observations were last refreshed on the tick (host clock).
    pub(super) last_evidence_refresh: Option<MonotonicTime>,
    /// The latest launches the backend refused, oldest first, at most [`MAX_KEPT_REFUSALS`]:
    /// a controlled negative launch reads its own here (the audit sink has them too).
    pub(super) refused: std::collections::VecDeque<crate::sandbox::integration::RefusedLaunch>,
    pub(super) shutting_down: bool,
    /// The sandboxes' publications and the connection gate (M14).
    pub(super) publications: super::publish::Publications,
}

/// Takes a delivery of `sandbox`'s boot in: ended commands become outcomes, a closed link
/// is noted.
fn take_delivery<S: Read + Write + StreamShutdown>(
    boot: &mut Boot<S>,
    sandbox: &ExecutionId,
    delivery: Delivery,
    taken: &mut Taken,
) {
    for event in delivery.commands {
        if let CommandEvent::Ended(result) = event {
            take_result(boot, sandbox, *result, taken, false);
        }
    }
    for event in delivery.egress {
        forward_egress(boot, sandbox, event, taken);
    }
    for event in delivery.ingress {
        forward_ingress(boot, sandbox, event, taken);
    }
    if let Some(cause) = delivery.closed {
        boot.link_closed = Some(cause);
    }
}

/// Takes one ended command in: its lease is given back, its outcome waits for its caller,
/// and the first command that exits 0 is marked as the sandbox's first command.
fn take_result<S: Read + Write + StreamShutdown>(
    boot: &mut Boot<S>,
    sandbox: &ExecutionId,
    result: CommandResult,
    taken: &mut Taken,
    by_closure: bool,
) {
    let number = result.stream.get();
    if let Some(lease) = boot.running.remove(&number) {
        taken.leases.push(lease);
    }
    let outcome = ExecOutcome::of(result);
    if outcome.end == ExecEnd::Finished && outcome.exit_code == Some(0) && !boot.first_command {
        boot.first_command = true;
        taken.first_commands.push(sandbox.clone());
    }
    if by_closure {
        boot.ended_by_closure.push(outcome.command);
    }
    while boot.outcomes.len() >= MAX_UNCLAIMED_OUTCOMES {
        boot.outcomes.pop_first();
    }
    boot.outcomes.insert(number, outcome);
}

/// Writes `frames` to a stream whose driver is gone, retrying a write that would block
/// until `deadline`, then shuts the stream down. Returns whether every frame was written.
fn write_final<S: Write + StreamShutdown>(
    mut stream: S,
    frames: &[Vec<u8>],
    deadline: Instant,
) -> bool {
    let mut written = !frames.is_empty();
    'frames: for frame in frames {
        let mut rest: &[u8] = frame;
        while !rest.is_empty() {
            match stream.write(rest) {
                Ok(0) => {
                    written = false;
                    break 'frames;
                }
                Ok(count) => rest = rest.get(count..).unwrap_or_default(),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(_) => {
                    written = false;
                    break 'frames;
                }
            }
        }
    }
    let flushed = stream.flush().is_ok();
    let shut = stream.shut_down().is_ok();
    written && flushed && shut
}

/// A deadline `bound` from now, or as far as the clock reaches.
pub(super) fn deadline_after(bound: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(bound).unwrap_or(now)
}

/// Waits until each driver ended or `bound` passed, joins those that ended, and returns
/// how many it joined and the sandboxes of those it left.
pub(super) fn join_within(
    handles: Vec<(ExecutionId, JoinHandle<()>)>,
    bound: Duration,
) -> (usize, Vec<(ExecutionId, JoinHandle<()>)>) {
    let deadline = deadline_after(bound);
    let mut joined = 0;
    let mut pending = handles;
    loop {
        let (finished, rest): (Vec<_>, Vec<_>) = pending
            .into_iter()
            .partition(|(_, handle)| handle.is_finished());
        for (_, handle) in finished {
            // A driver that panicked ended all the same.
            let _ = handle.join();
            joined += 1;
        }
        pending = rest;
        if pending.is_empty() || Instant::now() >= deadline {
            return (joined, pending);
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// The transport driver of `sandbox`'s boot: passes over its pump until the pump finished
/// or the service shuts down.
pub(super) fn drive<P: VmPorts>(shared: Arc<Shared<P>>, sandbox: ExecutionId) {
    loop {
        let (pass, poll) = {
            let mut core = shared.lock();
            let pass = core.drive_once(&sandbox);
            (pass, core.settings.poll_interval)
        };
        match pass {
            DriverPass::Busy => {
                shared.notify();
                thread::yield_now();
            }
            DriverPass::Idle => thread::sleep(poll),
            DriverPass::Stop => {
                shared.notify();
                return;
            }
        }
    }
}

/// Starts `sandbox`'s driver thread.
pub(super) fn spawn_driver<P: VmPorts>(
    shared: &Arc<Shared<P>>,
    sandbox: &ExecutionId,
) -> std::io::Result<JoinHandle<()>> {
    let shared = Arc::clone(shared);
    let execution = sandbox.clone();
    thread::Builder::new()
        .name(format!("vm-link-{}", sandbox.as_str()))
        .spawn(move || drive(shared, execution))
}

impl<P: VmPorts> Core<P> {
    pub(super) fn new(
        host: ServiceHost<P>,
        connector: P::Connector,
        processes: P::Processes,
        settings: Settings,
    ) -> Self {
        Self {
            host: Some(host),
            boots: BTreeMap::new(),
            connector,
            processes,
            settings,
            last_tick: None,
            last_evidence_refresh: None,
            refused: std::collections::VecDeque::new(),
            shutting_down: false,
            publications: super::publish::Publications::new(),
        }
    }

    pub(super) fn open(&self) -> Result<(), VmServiceError> {
        if self.shutting_down || self.host.is_none() {
            return Err(VmServiceError::ShuttingDown);
        }
        Ok(())
    }

    // ----- the driver's pass -------------------------------------------------------------

    /// One pass of `sandbox`'s driver: steps its pump, ticks the host when due, and
    /// finishes the endings whose VM stopped.
    pub(super) fn drive_once(&mut self, sandbox: &ExecutionId) -> DriverPass {
        if self.shutting_down {
            return DriverPass::Stop;
        }
        let Some(moved) = self.run_pump(sandbox, PumpCall::Step) else {
            return DriverPass::Stop;
        };
        self.tick_if_due();
        self.settle_endings();
        self.pump_egress(sandbox);
        self.pump_ingress(sandbox);
        self.pump_connections(sandbox);
        let carried = self
            .boots
            .get(sandbox)
            .is_some_and(|boot| boot.pump.is_some());
        match (carried, moved) {
            (false, _) => DriverPass::Stop,
            (true, true) => DriverPass::Busy,
            (true, false) => DriverPass::Idle,
        }
    }

    /// Steps or flushes `sandbox`'s pump and takes in what it produced; drops the pump,
    /// and with it the stream, once it finished. `None` when the boot has no pump; else
    /// whether anything moved.
    fn run_pump(&mut self, sandbox: &ExecutionId, call: PumpCall) -> Option<bool> {
        let mut taken = Taken::default();
        let moved = {
            let Core { host, boots, .. } = self;
            let host = host.as_mut()?;
            let boot = boots.get_mut(sandbox)?;
            let pump = boot.pump.as_mut()?;
            let before = pump.counters();
            let events = match call {
                PumpCall::Step => pump.step(host),
                PumpCall::Flush => pump.flush(host),
            };
            let counters = pump.counters();
            let finished = match pump.phase() {
                DriverPhase::Finished { end } => Some(end),
                _ => None,
            };
            // Progress is bytes or frames, never the number of calls: an idle non-blocking
            // stream answers every read with "would block", and counting those as movement
            // kept the driver from ever sleeping.
            let moved = !events.is_empty() || counters.progressed_since(&before);
            boot.counters = counters;
            for event in events {
                match event {
                    PumpEvent::Delivered(delivery) => {
                        take_delivery(boot, sandbox, delivery, &mut taken);
                    }
                    PumpEvent::Transport(TransportEvent::Finished { end }) => {
                        boot.transport_end = Some(end);
                    }
                    PumpEvent::Refused(_)
                    | PumpEvent::Transport(_)
                    | PumpEvent::ShutDown { .. }
                    | PumpEvent::EndNotReported(_) => {}
                }
            }
            if let Some(end) = finished {
                boot.transport_end.get_or_insert(end);
                boot.pump = None;
            }
            moved
        };
        self.settle_taken(taken);
        self.absorb_log();
        Some(moved)
    }

    /// Flushes every pump: after a tick or a call that queued frames.
    fn flush_all(&mut self) {
        let carried: Vec<ExecutionId> = self
            .boots
            .iter()
            .filter(|(_, boot)| boot.pump.is_some())
            .map(|(execution, _)| execution.clone())
            .collect();
        for sandbox in &carried {
            self.run_pump(sandbox, PumpCall::Flush);
        }
    }

    /// Flushes `sandbox`'s pump.
    pub(super) fn flush(&mut self, sandbox: &ExecutionId) {
        self.run_pump(sandbox, PumpCall::Flush);
    }

    /// Ticks the host when the tick interval passed on the host clock since the last
    /// tick: leases are enforced, revocations advanced, link timeouts and command
    /// deadlines applied; then every pump writes what that queued.
    pub(super) fn tick_if_due(&mut self) {
        self.tick_remote();
        let mut taken = Taken::default();
        {
            let Core {
                host,
                boots,
                settings,
                last_tick,
                last_evidence_refresh,
                ..
            } = self;
            let Some(host) = host.as_mut() else {
                return;
            };
            let now = host.clock().now();
            if last_tick
                .is_some_and(|last| now.saturating_duration_since(last) < settings.tick_interval)
            {
                return;
            }
            *last_tick = Some(now);
            // The probes observe the hypervisor and the runtime again before the tick's
            // readiness re-observation judges them, so a sandbox that outlives the minute
            // the launch's required properties allow stays admitted on current evidence. A
            // refused refresh leaves the last observation, which the judgment then finds
            // stale and reports as such; the next tick tries again.
            if last_evidence_refresh.map_or(true, |last| {
                now.saturating_duration_since(last) >= settings.evidence_refresh_interval
            }) {
                *last_evidence_refresh = Some(now);
                let additional = host.backend().additional_evidence();
                let registry = host.registry_mut();
                let _ = registry.refresh(
                    Capability::HypervisorAvailable,
                    &Subject::Hypervisor(settings.evidence.hypervisor),
                );
                let _ = registry.refresh(
                    Capability::RuntimeCategory,
                    &Subject::Runtime(settings.evidence.runtime.clone()),
                );
                for subjects in additional {
                    let _ = registry.refresh(Capability::HypervisorAvailable, &Subject::Hypervisor(subjects.hypervisor));
                    let _ = registry.refresh(Capability::RuntimeCategory, &Subject::Runtime(subjects.runtime));
                }
            }
            // A refused tick changed nothing of its own; the next tick tries again.
            if let Ok(tick) = host.tick() {
                for (execution, delivery) in tick.deliveries {
                    if let Some(boot) = boots.get_mut(&execution) {
                        take_delivery(boot, &execution, delivery, &mut taken);
                    }
                }
                // A sandbox the supervisor revoked on its own (an expired lease, a clock
                // rolled back) is asked for one authorization, as `end` asks: its refusal
                // is the observed denial of new work, so the revocation's report shows it
                // instead of leaving it pending until someone tries a command (found 30
                // October 2026 on an expired idle lease).
                let revoked = tick
                    .supervisor
                    .expired
                    .iter()
                    .map(|(execution, _)| execution)
                    .chain(tick.supervisor.clock_rolled_back.iter());
                for execution in revoked {
                    observe_denial::<P>(host, execution);
                }
            }
        }
        self.settle_taken(taken);
        self.absorb_log();
        self.flush_all();
        self.settle_endings();
    }

    /// Gives back the leases of ended commands and marks first commands.
    fn settle_taken(&mut self, taken: Taken) {
        let Core { host, boots, .. } = self;
        let Some(host) = host.as_mut() else {
            return;
        };
        for (sandbox, stream) in &taken.egress_cancels {
            let events = host.cancel_egress(sandbox, *stream).unwrap_or_default();
            if let Some(boot) = boots.get_mut(sandbox) {
                let mut ignored = Taken::default();
                for event in events {
                    forward_egress(boot, sandbox, event, &mut ignored);
                }
                // A connection's stream is gone whatever the link said.
                if let Some(shared) = boot.connections.remove(&stream.get()) {
                    shared.ended("the host cancelled the stream".to_owned());
                    shared.release_credit();
                }
            }
        }
        let mut credit: Vec<(ExecutionId, StreamId, u64)> = taken.ingress_credit.clone();
        for (sandbox, stream) in &taken.ingress_cancels {
            let events = host.cancel_ingress(sandbox, *stream).unwrap_or_default();
            if let Some(boot) = boots.get_mut(sandbox) {
                let mut more = Taken::default();
                for event in events {
                    forward_ingress(boot, sandbox, event, &mut more);
                }
                credit.extend(more.ingress_credit);
                // Gone whatever the link said (already ended, or the channels closed); its
                // window went with it.
                if let Some(shared) = boot.ingress.remove(&stream.get()) {
                    shared.ended("the host cancelled the stream".to_owned());
                    shared.release_credit();
                }
            }
        }
        for (sandbox, stream, bytes) in credit {
            if bytes > 0 {
                // A credit's own events are of streams the boot already forgot.
                let _ = host.consume_ingress(&sandbox, stream, bytes);
            }
        }
        if !taken.leases.is_empty() {
            host.with_supervisor(|supervisor, _, _| {
                for lease in &taken.leases {
                    // A lease the coordinator no longer holds (expired, or ended with a
                    // revocation) needs no release.
                    let _ = supervisor.coordinator_mut().release_lease(*lease);
                }
            });
        }
        for sandbox in &taken.first_commands {
            // The BENCH-05 clock; refused once the link closed, which loses nothing.
            let _ = host.first_command(sandbox);
        }
        for (sandbox, stream, endpoint, shared) in taken.connection_opens {
            self.open_connection(&sandbox, stream, &endpoint, shared);
        }
    }

    /// Joins a stream `caller`'s program opened to its connection endpoint `endpoint` to the
    /// service the endpoint is granted, through the gate (module docs in `connect`): the
    /// callee's guest is asked to open its service's port only once the gate admitted the
    /// connection. Granted nothing, the callee not ready, or refused by the gate, the stream
    /// is cancelled and the refusal counted.
    fn open_connection(
        &mut self,
        caller: &ExecutionId,
        _stream: StreamId,
        endpoint: &LinkName,
        shared: Arc<IngressShared>,
    ) {
        let mut caller_end = GuestIngress::new(shared);
        let callee_end = self
            .publications
            .binding(caller, endpoint.as_str())
            .and_then(|binding| {
                let listener = LinkName::new(binding.service.listener()).ok()?;
                self.ingress(&SandboxId::new(binding.callee), listener).ok()
            });
        let Some(mut callee_end) = callee_end else {
            use crate::sandbox_contract::connections::SessionStream as _;
            caller_end.close();
            self.publications.refused_connection(caller);
            return;
        };
        let callee_room = callee_end.watch();
        caller_end.set_caller_room(Arc::new(move || callee_room.room()));
        let caller_room = caller_end.watch();
        callee_end.set_caller_room(Arc::new(move || caller_room.room()));
        let connected = {
            let Core {
                host, publications, ..
            } = self;
            match host.as_ref() {
                Some(host) => publications
                    .connect(
                        host.supervisor().coordinator(),
                        caller,
                        endpoint.as_str(),
                        Box::new(caller_end),
                        Box::new(callee_end),
                    )
                    .is_ok(),
                None => false,
            }
        };
        if connected {
            self.hold_published_channels();
        }
    }

    /// Takes what the host recorded: every closure of a boot's channels ends its commands
    /// with the closure's cause.
    pub(super) fn absorb_log(&mut self) {
        for _ in 0..4 {
            let mut taken = Taken::default();
            {
                let Core {
                    host,
                    boots,
                    refused,
                    ..
                } = self;
                let Some(host) = host.as_mut() else {
                    return;
                };
                let log = host.take_log();
                for (refusal, _) in log.audit.refusals {
                    if refused.len() == MAX_KEPT_REFUSALS {
                        refused.pop_front();
                    }
                    refused.push_back(refusal);
                }
                if log.closures.is_empty() {
                    return;
                }
                for closure in log.closures {
                    if let Some(boot) = boots.get_mut(&closure.execution) {
                        for result in closure.commands {
                            take_result(boot, &closure.execution, result, &mut taken, true);
                        }
                        for event in closure.egress {
                            forward_egress(boot, &closure.execution, event, &mut taken);
                        }
                        for event in closure.ingress {
                            forward_ingress(boot, &closure.execution, event, &mut taken);
                        }
                        end_ingress_requests(boot, "the sandbox's channels closed");
                    }
                }
            }
            self.settle_taken(taken);
        }
    }

    // ----- launch ------------------------------------------------------------------------

    /// The runtime, admitted as a VM sandbox on evidence the host's probes observe now.
    fn admit_runtime(&mut self, subjects: &EvidenceSubjects) -> Result<AdmittedRuntime, VmServiceError> {
        let Core { host, settings, .. } = self;
        let host = host.as_mut().ok_or(VmServiceError::ShuttingDown)?;
        let evidence =
            |step: EvidenceStep, detail: String| VmServiceError::Evidence { step, detail };
        let registry = host.registry_mut();
        registry
            .refresh(
                Capability::HypervisorAvailable,
                &Subject::Hypervisor(subjects.hypervisor),
            )
            .map_err(|error| evidence(EvidenceStep::Hypervisor, error.to_string()))?;
        registry
            .refresh(
                Capability::RuntimeCategory,
                &Subject::Runtime(subjects.runtime.clone()),
            )
            .map_err(|error| evidence(EvidenceStep::RuntimeCategory, error.to_string()))?;
        let offer = RuntimeOffer::observe(
            host.registry(),
            subjects.runtime.clone(),
            settings.runtime_evidence_max_age,
            settings.image.configuration,
        )
        .map_err(|error| evidence(EvidenceStep::Offer, error.to_string()))?;
        RuntimeRequirement::VmSandbox
            .admit(&offer)
            .map_err(|error| evidence(EvidenceStep::Admission, error.to_string()))
    }

    /// The launch up to the transport driver: the launch transaction, then the boot's link
    /// socket, secret, nonce, channels and pump. A failure after the VM exists revokes the
    /// sandbox to stop it.
    pub(super) fn begin_launch(
        &mut self,
        sandbox: &ExecutionId,
        spec: &LaunchSpec,
    ) -> Result<(), VmServiceError> {
        self.open()?;
        super::publish::check_published(&spec.published)
            .map_err(|detail| VmServiceError::Ingress { detail })?;
        let network = super::publish::launch_grants(&spec.published)
            .map_err(|detail| VmServiceError::Ingress { detail })?;
        let service_ports: Vec<u16> = spec
            .published
            .iter()
            .map(|published| published.port)
            .collect();
        super::connect::check_connect(&spec.connect, &service_ports)
            .map_err(|detail| VmServiceError::Connection { detail })?;
        let endpoints =
            launch_endpoints(spec).map_err(|detail| VmServiceError::Connection { detail })?;
        let (selected_profile, subjects) = self.host.as_ref().ok_or(VmServiceError::ShuttingDown)?
            .backend().launch_profile(spec.gpu, self.settings.profile.clone(), self.settings.evidence.clone())
            .map_err(|detail| VmServiceError::Evidence { step: EvidenceStep::Admission, detail })?;
        let runtime = self.admit_runtime(&subjects)?;
        let mut demand = BTreeMap::from([
            (ResourceKind::HostMemoryBytes, spec.resources.memory_bytes),
            (ResourceKind::CpuInitializationSlots, spec.resources.cpu_slots),
        ]);
        if spec.gpu != !spec.gpu_memory.is_empty() {
            return Err(VmServiceError::Evidence { step: EvidenceStep::Admission, detail: "GPU acceleration requires a host-observed GPU memory reservation.".into() });
        }
        for (device, amount) in &spec.gpu_memory {
            if *amount == 0 || demand.insert(ResourceKind::GpuMemoryBytes { device: *device }, *amount).is_some() {
                return Err(VmServiceError::Evidence { step: EvidenceStep::Admission, detail: "Invalid GPU memory reservation.".into() });
            }
        }
        let request = LaunchRequest {
            execution: sandbox.clone(),
            tenant: spec.tenant.clone(),
            runtime,
            demand,
            priority: ReservationPriority::Foreground,
            class: SandboxClass::Task,
            // Checked by `VmService::launch` before anything was reserved.
            limits: spec
                .lease_limits()
                .unwrap_or_else(|_| LeaseLimits::defaults(SandboxClass::Task)),
            // The published services' grants and nothing more (M14).
            settings: SettingsGrant {
                network,
                ..SettingsGrant::default()
            },
            volumes: BTreeMap::new(),
            provider_bills: false,
        };
        let launched = {
            let Core { host, .. } = self;
            let host = host.as_mut().ok_or(VmServiceError::ShuttingDown)?;
            // The launch profile is the service's, with this launch's declared endpoints. A
            // launch with endpoints may hold typed operations through its relay (strict
            // action mode: the broker answers declared operations only), so its record's
            // network requirement names that channel; the VM itself stays without a network
            // device, which the backend observes.
            let mut profile = selected_profile;
            #[cfg(feature = "acceptance")]
            plant_gpu_request(&mut profile);
            profile.required.declared_endpoints = endpoints;
            profile.required.workload_image = spec.workload_image.clone();
            // A launch that publishes a service may carry its callers' streams, and one with
            // connection endpoints its programs' streams to granted services of other
            // sandboxes (named, unparsed transport); the VM itself stays without a network
            // device either way.
            let mut channels = Vec::new();
            if spec.internet { channels.push(NetworkChannel::Internet); }
            if !spec.egress_endpoints.is_empty() {
                channels.push(NetworkChannel::TypedCredentialedOperations);
            }
            if !spec.published.is_empty() {
                channels.push(NetworkChannel::PublishedService);
            }
            if !spec.connect.is_empty() {
                channels.push(NetworkChannel::NamedTransportRoutes);
            }
            if !channels.is_empty() {
                profile.required.network = NetworkAuthority::of(channels);
            }
            host.set_profile(sandbox.clone(), profile);
            host.launch(request)
        };
        self.absorb_log();
        let id = SandboxId::new(sandbox.clone());
        let boot = match launched.map_err(|error| VmServiceError::of_host(&id, error, None))? {
            LaunchReceipt::AuthorityActive { boot, .. } => boot,
            LaunchReceipt::Queued { position, .. } => {
                return Err(VmServiceError::LaunchQueued { position })
            }
            LaunchReceipt::RolledBack { failure, .. } => {
                return Err(VmServiceError::LaunchRolledBack { failure })
            }
            LaunchReceipt::RollbackStalled { failure, stall, .. } => {
                return Err(VmServiceError::LaunchRollbackStalled { failure, stall })
            }
        };
        let (vm, process, directory) = {
            let host = self.host.as_ref().ok_or(VmServiceError::ShuttingDown)?;
            let vm = host
                .supervisor()
                .coordinator()
                .sandbox(sandbox)
                .and_then(SandboxLifecycle::vm);
            let process = vm.and_then(|vm| host.backend().process_of(&vm));
            let directory =
                process.and_then(|process| host.backend().private_directory(&process));
            (vm, process, directory)
        };
        self.boots.insert(
            sandbox.clone(),
            Boot::new(boot, vm, process, directory.clone()),
        );
        if let Err((step, cause)) =
            self.connect_boot(sandbox, process, directory, spec.workload_image.is_some())
        {
            let cleanup = self.abandon(sandbox, cause);
            return Err(VmServiceError::LaunchFailed {
                sandbox: id,
                step,
                cleanup,
            });
        }
        // Its declared services and connection endpoints attach to the gate with its fresh
        // authority; nothing is published or connected until asked.
        if !spec.published.is_empty() || !spec.connect.is_empty() {
            let attached = {
                let Core {
                    host,
                    publications,
                    boots,
                    ..
                } = self;
                match host.as_mut() {
                    Some(host) => {
                        let names: BTreeSet<LinkName> = spec
                            .connect
                            .iter()
                            .filter_map(|endpoint| endpoint.guest_endpoint().ok())
                            .filter_map(|endpoint| LinkName::new(endpoint.name()).ok())
                            .collect();
                        let accepted = if names.is_empty() {
                            Ok(())
                        } else {
                            host.accept_connections(sandbox, names.clone())
                                .map_err(|error| format!("the host refused the endpoints: {error}"))
                        };
                        if let Some(boot) = boots.get_mut(sandbox) {
                            boot.connection_names = names;
                        }
                        accepted.and_then(|()| {
                            publications.attach(
                                host.supervisor().coordinator(),
                                sandbox,
                                &spec.published,
                                &spec.connect,
                                spec.owner_session,
                            )
                        })
                    }
                    None => Err("the service is shutting down".to_owned()),
                }
            };
            if let Err(detail) = attached {
                let cleanup = self.abandon(sandbox, RevocationCause::UserRequested);
                return Err(VmServiceError::LaunchFailed {
                    sandbox: id,
                    step: LaunchStep::Publications { detail },
                    cleanup,
                });
            }
        }
        Ok(())
    }

    /// The boot's link: the checked socket, the secret, a fresh nonce, the channels and
    /// the pump. A refusal names the step and the revocation cause it calls for.
    fn connect_boot(
        &mut self,
        sandbox: &ExecutionId,
        process: Option<ProcessIdentity>,
        directory: Option<PrivateDirectory>,
        image: bool,
    ) -> Result<(), (LaunchStep, RevocationCause)> {
        let ordinary = RevocationCause::UserRequested;
        let process = process.ok_or((LaunchStep::NoProcess, ordinary))?;
        let directory = directory.ok_or((LaunchStep::NoPrivateDirectory, ordinary))?;
        let endpoint = LinkSocketEndpoint::new(&directory, process);
        let checked = endpoint
            .connect(&mut self.connector, &self.processes)
            .map_err(|refusal| {
                let cause = match refusal {
                    EndpointRefusal::WrongPeer { .. } | EndpointRefusal::NotTheVmm { .. } => {
                        RevocationCause::Violation
                    }
                    _ => ordinary,
                };
                (LaunchStep::LinkSocket { refusal }, cause)
            })?;
        let opened = {
            let Core { host, settings, .. } = self;
            let host = host.as_mut().ok_or((LaunchStep::ShutDown, ordinary))?;
            let secret = host
                .backend_mut()
                .take_secret(&process)
                .ok_or((LaunchStep::NoSecret, ordinary))?;
            let connection = ConnectionNonce::draw()
                .map_err(|refusal| (LaunchStep::Nonce { refusal }, ordinary))?;
            host.open_channels(
                sandbox,
                ChannelSetup {
                    secret,
                    connection,
                    scope: TrustScope::named(ExecutionCategory::VmSandbox, sandbox.as_str()),
                    link_limits: LinkLimits {
                        open_timeout: if image {
                            Duration::from_secs(300)
                        } else {
                            LinkLimits::default().open_timeout
                        },
                        ..LinkLimits::default()
                    },
                    files_limits: FilesLimits::default(),
                    transfers: settings.transfers.clone(),
                    grants: Vec::new(),
                },
            )
        };
        self.absorb_log();
        opened.map_err(|error| {
            (
                LaunchStep::Channels {
                    refusal: HostRefusal::from(error),
                },
                ordinary,
            )
        })?;
        let pump = {
            let limits = self.settings.limits;
            let host = self.host.as_mut().ok_or((LaunchStep::ShutDown, ordinary))?;
            SessionPump::new(host, sandbox.clone(), checked, limits).map_err(|refusal| {
                (
                    LaunchStep::Pump {
                        detail: refusal.to_string(),
                    },
                    ordinary,
                )
            })?
        };
        if let Some(boot) = self.boots.get_mut(sandbox) {
            boot.pump = Some(pump);
        }
        Ok(())
    }

    /// Ends the stream of `sandbox`'s boot before its pump finished (a failed launch): the
    /// stream is shut down and the host learns the transport ended; then the pump is
    /// dropped, and the stream with it. A pump that finished is dropped as it is.
    fn abandon_pump(&mut self, sandbox: &ExecutionId) {
        let Core { host, boots, .. } = self;
        let Some(boot) = boots.get_mut(sandbox) else {
            return;
        };
        if let (Some(pump), Some(host)) = (boot.pump.as_mut(), host.as_mut()) {
            if !pump.is_finished() {
                let events = pump.abandon(host);
                for event in events {
                    if let PumpEvent::Transport(TransportEvent::Finished { end }) = event {
                        boot.transport_end.get_or_insert(end);
                    }
                }
            }
        }
        boot.pump = None;
        self.absorb_log();
    }

    /// Asks `sandbox`'s guest to shut down within the configured grace (the link's
    /// `Shutdown` message): the time of the request on the host clock and the grace it
    /// named, or why it was not sent.
    pub(super) fn request_guest_shutdown(
        &mut self,
        sandbox: &ExecutionId,
    ) -> Result<(MonotonicTime, u32), ShutdownNotRequested> {
        let grace = self.settings.shutdown_grace;
        let grace_seconds = u32::try_from(grace.as_secs()).unwrap_or(u32::MAX);
        let requested = {
            let host = self.host.as_mut().ok_or(ShutdownNotRequested::Refused {
                detail: VmServiceError::ShuttingDown.to_string(),
            })?;
            host.request_shutdown(sandbox, grace)
        };
        self.absorb_log();
        let at = match requested {
            Ok(()) => self.now().ok_or(ShutdownNotRequested::Refused {
                detail: VmServiceError::ShuttingDown.to_string(),
            })?,
            Err(HostError::LinkNotOpen { .. }) => return Err(ShutdownNotRequested::LinkNotOpen),
            Err(HostError::ChannelsClosed { .. } | HostError::NoChannels { .. }) => {
                return Err(ShutdownNotRequested::ChannelsClosed)
            }
            Err(other) => {
                return Err(ShutdownNotRequested::Refused {
                    detail: other.to_string(),
                })
            }
        };
        // The urgent frame goes out now.
        self.flush(sandbox);
        Ok((at, grace_seconds))
    }

    /// Whether the host observed `sandbox`'s guest gone after a shutdown request: its
    /// stream ended (the pump finished) or its link closed, or the backend sees its process
    /// ended. `None` while it is still there.
    pub(super) fn guest_gone(&self, sandbox: &ExecutionId) -> Option<GuestShutdownOutcome> {
        let host = self.host.as_ref()?;
        let at = host.clock().now();
        let boot = self.boots.get(sandbox)?;
        let link_gone = boot.pump.is_none()
            || boot.transport_end.is_some()
            || boot.link_closed.is_some()
            || host
                .session(sandbox)
                .is_none_or(|session| !session.takes_bytes());
        if link_gone {
            return Some(GuestShutdownOutcome::LinkClosed { at });
        }
        let process_ended = boot.process.is_some_and(|process| {
            matches!(
                host.backend().process_state(&process),
                Ok(crate::sandbox::qemu::ProcessState::Ended { .. })
            )
        });
        process_ended.then_some(GuestShutdownOutcome::ProcessEnded { at })
    }

    /// Where `sandbox`'s handshake stands.
    pub(super) fn hello(&self, sandbox: &ExecutionId) -> Hello {
        let (Some(host), Some(boot)) = (self.host.as_ref(), self.boots.get(sandbox)) else {
            return Hello::Failed(LaunchStep::ShutDown);
        };
        let Some(session) = host.session(sandbox) else {
            return Hello::Failed(LaunchStep::ChannelsClosed);
        };
        match session.link().map(HostLink::phase) {
            Some(LinkPhase::Open) => Hello::Open,
            Some(LinkPhase::Closed(cause)) => Hello::Failed(LaunchStep::NoHello {
                cause: cause.clone(),
            }),
            Some(LinkPhase::AwaitingHello) if boot.pump.is_none() => {
                Hello::Failed(LaunchStep::TransportEnded {
                    end: boot.transport_end,
                })
            }
            Some(LinkPhase::AwaitingHello) => Hello::Waiting,
            None => Hello::Failed(LaunchStep::ChannelsClosed),
        }
    }

    /// Marks `sandbox`'s boot ready, once its handshake completed.
    pub(super) fn mark_ready(&mut self, sandbox: &ExecutionId) {
        if let Some(boot) = self.boots.get_mut(sandbox) {
            if boot.phase == BootPhase::Starting {
                boot.phase = BootPhase::Ready;
            }
        }
    }

    /// Ends a launch that failed after its VM existed: the sandbox is revoked for `cause`,
    /// which closes whatever channel opened and stops the VM through its handle; a pump
    /// still carrying the stream is abandoned, so the host learns the stream ended and
    /// acknowledges the channels closed. Returns how far that got.
    pub(super) fn abandon(
        &mut self,
        sandbox: &ExecutionId,
        cause: RevocationCause,
    ) -> LaunchCleanup {
        let revocation_refused = match self.end(sandbox, cause) {
            Ok(_) => None,
            Err(VmServiceError::Host { refusal }) => Some(refusal),
            Err(VmServiceError::Supervisor { error }) => Some(HostRefusal::Supervisor { error }),
            Err(other) => Some(HostRefusal::Other {
                detail: other.to_string(),
            }),
        };
        self.abandon_pump(sandbox);
        if let Some(boot) = self.boots.get_mut(sandbox) {
            boot.phase = BootPhase::Ended;
        }
        self.settle_ending(sandbox);
        let (vm_stop, directory) = self.ending_of(sandbox);
        let channels_open = self
            .host
            .as_ref()
            .and_then(|host| host.session(sandbox))
            .is_some_and(BootSession::is_open);
        LaunchCleanup {
            revocation_refused,
            vm_stop,
            directory,
            channels_open,
        }
    }

    // ----- commands ----------------------------------------------------------------------

    pub(super) fn ready_boot(
        &self,
        sandbox: &SandboxId,
    ) -> Result<&Boot<StreamOf<P>>, VmServiceError> {
        let Some(boot) = self.boots.get(sandbox.execution()) else {
            // A sandbox the supervisor knows without a boot of this run (recovered after a
            // restart, or ended before this run) is not ready, not unknown.
            return Err(if self.knows(sandbox.execution()) {
                VmServiceError::NotReady {
                    sandbox: sandbox.clone(),
                    phase: BootPhase::Ended,
                }
            } else {
                VmServiceError::UnknownSandbox {
                    sandbox: sandbox.clone(),
                }
            });
        };
        match boot.phase {
            BootPhase::Ready => Ok(boot),
            phase => Err(VmServiceError::NotReady {
                sandbox: sandbox.clone(),
                phase,
            }),
        }
    }

    /// Starts one command: authorized as CORE-04 child work on fresh readiness, then a
    /// terminal stream on the boot's link; the activity is recorded and the open written.
    pub(super) fn start_command(
        &mut self,
        sandbox: &SandboxId,
        request: ExecRequest,
    ) -> Result<CommandId, VmServiceError> {
        self.open()?;
        self.authorize_remote(sandbox)?;
        let link_closed = self.ready_boot(sandbox)?.link_closed.clone();
        let execution = sandbox.execution();
        let term = request.deadline.saturating_add(self.settings.tick_interval);
        let authorized = {
            let host = self.host.as_mut().ok_or(VmServiceError::ShuttingDown)?;
            host.authorize_work(
                execution,
                OperationId::generate(),
                LeaseKind::ChildWork,
                CallTerms {
                    per_call: term,
                    task: term,
                },
                BTreeSet::new(),
            )
        };
        self.absorb_log();
        let lease = authorized
            .map_err(|error| VmServiceError::of_host(sandbox, error, link_closed.clone()))?;
        let started = {
            let host = self.host.as_mut().ok_or(VmServiceError::ShuttingDown)?;
            let started = host.start_command(
                execution,
                CommandRequest {
                    image_entrypoint: request.image_entrypoint,
                    input: request.input,
                    max_output_bytes: request.max_output_bytes,
                    time_limit: request.deadline,
                    columns: TERMINAL_COLUMNS,
                    rows: TERMINAL_ROWS,
                },
            );
            if started.is_ok() {
                // Typed activity resets the idle limit (§6.2); a refusal changes nothing.
                let _ = host.with_supervisor(|supervisor, _, _| {
                    supervisor.activity(execution, ActivityKind::Command)
                });
            }
            started
        };
        let stream = match started {
            Ok(stream) => stream,
            Err(error) => {
                self.settle_taken(Taken {
                    leases: vec![lease.id()],
                    ..Taken::default()
                });
                self.absorb_log();
                return Err(VmServiceError::of_host(sandbox, error, link_closed));
            }
        };
        if let Some(boot) = self.boots.get_mut(execution) {
            boot.running.insert(stream.get(), lease.id());
        }
        self.absorb_log();
        self.flush(execution);
        Ok(CommandId::of(stream))
    }

    /// The outcome of `command`, if it ended; `Ok(None)` while it runs.
    pub(super) fn claim(
        &mut self,
        sandbox: &SandboxId,
        command: CommandId,
    ) -> Result<Option<ExecOutcome>, VmServiceError> {
        let shut = self.host.is_none();
        let boot = self.boots.get_mut(sandbox.execution()).ok_or_else(|| {
            VmServiceError::UnknownSandbox {
                sandbox: sandbox.clone(),
            }
        })?;
        if let Some(outcome) = boot.outcomes.remove(&command.get()) {
            return Ok(Some(outcome));
        }
        if !boot.running.contains_key(&command.get()) {
            return Err(VmServiceError::UnknownCommand {
                sandbox: sandbox.clone(),
                command,
            });
        }
        if shut {
            return Err(VmServiceError::ShuttingDown);
        }
        Ok(None)
    }

    /// Cancels a running command; its outcome says it was cancelled by the caller. A
    /// command that ended already is left as it ended.
    pub(super) fn cancel_command(
        &mut self,
        sandbox: &SandboxId,
        command: CommandId,
    ) -> Result<(), VmServiceError> {
        self.open()?;
        let execution = sandbox.execution();
        let boot = self
            .boots
            .get(execution)
            .ok_or_else(|| VmServiceError::UnknownSandbox {
                sandbox: sandbox.clone(),
            })?;
        let unknown = VmServiceError::UnknownCommand {
            sandbox: sandbox.clone(),
            command,
        };
        if boot.outcomes.contains_key(&command.get()) {
            return Ok(());
        }
        if !boot.running.contains_key(&command.get()) {
            return Err(unknown);
        }
        let link_closed = boot.link_closed.clone();
        let stream = command.stream().ok_or(unknown)?;
        let cancelled = {
            let host = self.host.as_mut().ok_or(VmServiceError::ShuttingDown)?;
            host.cancel_command(execution, stream)
        };
        let mut taken = Taken::default();
        let refused = match cancelled {
            Ok(result) => {
                if let Some(boot) = self.boots.get_mut(execution) {
                    take_result(boot, execution, result, &mut taken, false);
                }
                None
            }
            Err(error) => Some(error),
        };
        self.settle_taken(taken);
        self.absorb_log();
        self.flush(execution);
        match refused {
            None => Ok(()),
            // The command ended meanwhile (a revocation or a deadline in the same call).
            Some(_)
                if self
                    .boots
                    .get(execution)
                    .is_some_and(|boot| boot.outcomes.contains_key(&command.get())) =>
            {
                Ok(())
            }
            Some(error) => Err(VmServiceError::of_host(sandbox, error, link_closed)),
        }
    }

    // ----- revocation and stop -----------------------------------------------------------

    /// Revokes `sandbox` for `cause` and takes it as far as it goes now (§6.3): the
    /// supervisor's revocation closes the boot's channels; one authorization is asked for
    /// so its refusal is the observed denial of new work; the leases of the commands the
    /// closure ended are given back and the revocation advanced, which stops the VM
    /// through its handle once the gate opens; the close frame is written; and the ending
    /// is observed. Revoking again changes nothing and reports where it stands.
    pub(super) fn end(
        &mut self,
        sandbox: &ExecutionId,
        cause: RevocationCause,
    ) -> Result<Ended, VmServiceError> {
        let id = SandboxId::new(sandbox.clone());
        self.close_remote(sandbox);
        if let Some(boot) = self.boots.get_mut(sandbox) {
            if boot.phase != BootPhase::Ended {
                boot.phase = BootPhase::Stopping;
            }
        }
        // Its callers' sessions and its connections close first: nothing more leaves once the
        // revocation is decided, and its channels are closed in fact only without them (M14).
        self.publications.close_channels_of(sandbox);
        self.hold_published_channels();
        let revoked = {
            let host = self.host.as_mut().ok_or(VmServiceError::ShuttingDown)?;
            host.revoke(sandbox, cause)
        };
        self.absorb_log();
        revoked.map_err(|error| VmServiceError::of_host(&id, error, None))?;
        if let Some(host) = self.host.as_mut() {
            observe_denial::<P>(host, sandbox);
        }
        self.absorb_log();
        if let Some(host) = self.host.as_mut() {
            // A refused advance is recorded by the supervisor as uncertain; the ending
            // below reports the VM as not stopped.
            let _ = host.advance(sandbox);
        }
        self.absorb_log();
        self.flush(sandbox);
        self.settle_ending(sandbox);
        let (vm_stop, directory) = self.ending_of(sandbox);
        let commands_ended = self
            .boots
            .get_mut(sandbox)
            .map(|boot| std::mem::take(&mut boot.ended_by_closure))
            .unwrap_or_default();
        Ok(Ended {
            vm_stop,
            directory,
            commands_ended,
        })
    }

    /// The report of `sandbox`'s revocation as it stands.
    pub(super) fn revocation_report(
        &self,
        sandbox: &SandboxId,
        reason: RevokeReason,
        ended: Ended,
    ) -> RevocationReport {
        let run = self
            .host
            .as_ref()
            .and_then(|host| host.supervisor().revocation(sandbox.execution()));
        let milestone = |acknowledgment: Acknowledgment| match run
            .and_then(|run| run.acknowledged_at(acknowledgment))
        {
            Some(at) => Milestone::Observed {
                at,
                source: run.and_then(|run| run.source(acknowledgment)),
            },
            None => Milestone::Pending,
        };
        RevocationReport {
            sandbox: sandbox.clone(),
            reason,
            cause: run.map_or(reason.cause(), RevocationRun::cause),
            decided_at: run.map(RevocationRun::decided_at),
            new_work_denied: milestone(Acknowledgment::NewAuthorizationsDenied),
            channels_closed: milestone(Acknowledgment::ChannelsClosed),
            vm_stopped: milestone(Acknowledgment::VmStopped),
            cleanup_done: milestone(Acknowledgment::CleanupFinished),
            vm_stop: ended.vm_stop,
            directory: ended.directory,
            commands_ended: ended.commands_ended,
            uncertain: run.map_or(0, |run| run.uncertain().len()),
        }
    }

    /// The host clock now, if the service runs.
    pub(super) fn now(&self) -> Option<MonotonicTime> {
        self.host.as_ref().map(|host| host.clock().now())
    }

    /// Whether the supervisor knows `sandbox`.
    pub(super) fn knows(&self, sandbox: &ExecutionId) -> bool {
        self.boots.contains_key(sandbox)
            || self
                .host
                .as_ref()
                .is_some_and(|host| host.supervisor().sandbox(sandbox).is_some())
    }

    /// Whether the VM of `sandbox` is stopped with the host's proof.
    fn vm_stop(&self, sandbox: &ExecutionId) -> VmStop {
        let Some(host) = self.host.as_ref() else {
            return VmStop::NotStopped {
                pending: Vec::new(),
                uncertain: 0,
            };
        };
        let run = host.supervisor().revocation(sandbox);
        let Some(at) = run.and_then(|run| run.acknowledged_at(Acknowledgment::VmStopped)) else {
            return VmStop::NotStopped {
                pending: run.map(RevocationRun::pending).unwrap_or_default(),
                uncertain: run.map_or(0, |run| run.uncertain().len()),
            };
        };
        let Some(boot) = self.boots.get(sandbox) else {
            return VmStop::StoppedWithoutProof { at };
        };
        let (Some(vm), Some(process)) = (boot.vm, boot.process) else {
            return VmStop::StoppedWithoutProof { at };
        };
        let expected = ProcessRole::VmHost {
            execution: sandbox.clone(),
            vm,
            boot: boot.boot,
        };
        match host.backend().termination(&vm) {
            Some(proof) if proof.identity() == process && *proof.role() == expected => {
                VmStop::Stopped { at, process }
            }
            _ => VmStop::StoppedWithoutProof { at },
        }
    }

    /// The host port's observation of `sandbox`'s private directory.
    fn observe_directory(&self, sandbox: &ExecutionId) -> DirectoryRemoval {
        let (Some(host), Some(boot)) = (self.host.as_ref(), self.boots.get(sandbox)) else {
            return DirectoryRemoval::NotChecked;
        };
        let Some(directory) = &boot.directory else {
            return DirectoryRemoval::NotChecked;
        };
        let path = directory.path().clone();
        match host.backend().directory_absent(directory) {
            Ok(true) => DirectoryRemoval::Removed {
                at: host.clock().now(),
                path,
            },
            Ok(false) => DirectoryRemoval::StillPresent { path },
            Err(failure) => DirectoryRemoval::NotObserved { path, failure },
        }
    }

    /// How `sandbox`'s ending was observed, or that its VM is not shown stopped.
    fn ending_of(&self, sandbox: &ExecutionId) -> (VmStop, DirectoryRemoval) {
        match self.boots.get(sandbox).and_then(|boot| boot.ending.clone()) {
            Some(ending) => (ending.vm_stop, ending.directory),
            None => (self.vm_stop(sandbox), DirectoryRemoval::NotChecked),
        }
    }

    /// Finishes every ending whose VM stopped.
    fn settle_endings(&mut self) {
        let open: Vec<ExecutionId> = self
            .boots
            .iter()
            .filter(|(_, boot)| !boot.torn_down)
            .map(|(execution, _)| execution.clone())
            .collect();
        for sandbox in &open {
            self.settle_ending(sandbox);
        }
    }

    /// Collects the host's proof of `sandbox`'s VM process when the supervisor recorded the
    /// VM stopped without the backend having stopped it: the process ended on its own (the
    /// guest powered off after a shutdown request, or crashed), so the handle check found
    /// it gone and the lifecycle had nothing to stop. The backend still holds the process
    /// and its private directory until the host observes the end and removes the files;
    /// this is that observation, through the backend's own stop, which asks nothing of a
    /// process that ended and takes the proof.
    fn collect_proof(&mut self, sandbox: &ExecutionId) {
        let Some(boot) = self.boots.get(sandbox) else {
            return;
        };
        let Some(vm) = boot.vm else {
            return;
        };
        let Some(host) = self.host.as_mut() else {
            return;
        };
        let recorded = host
            .supervisor()
            .revocation(sandbox)
            .is_some_and(|run| run.acknowledged_at(Acknowledgment::VmStopped).is_some());
        if !recorded
            || host.backend().termination(&vm).is_some()
            || host.backend().process_of(&vm).is_none()
        {
            return;
        }
        // The lifecycle recorded the stop already; this collects the host's proof.
        let _ = host.backend_mut().stop(&vm);
    }

    /// Once `sandbox`'s VM is recorded stopped: the proof and the private directory are
    /// observed once, the logical cleanup is recorded when both hold (§6.5: process ended,
    /// filename dropped), and the boot is torn down once its pump finished.
    fn settle_ending(&mut self, sandbox: &ExecutionId) {
        let observed = match self.boots.get(sandbox) {
            None => return,
            Some(boot) if boot.torn_down => return,
            Some(boot) => boot.ending.is_some(),
        };
        if !observed {
            self.collect_proof(sandbox);
            let vm_stop = self.vm_stop(sandbox);
            if !vm_stop.is_stopped() {
                return;
            }
            let directory = match vm_stop {
                VmStop::Stopped { .. } => self.observe_directory(sandbox),
                _ => DirectoryRemoval::NotChecked,
            };
            let proven = matches!(vm_stop, VmStop::Stopped { .. }) && directory.is_removed();
            if let Some(boot) = self.boots.get_mut(sandbox) {
                boot.ending = Some(Ending { vm_stop, directory });
                boot.phase = BootPhase::Ended;
            }
            if proven {
                if let Some(host) = self.host.as_mut() {
                    // Refused when it was recorded already or the cleanup never started;
                    // the revocation's milestones show which.
                    let _ = host.with_supervisor(|supervisor, _, _| {
                        supervisor.finish_cleanup(
                            sandbox,
                            CleanupReport::logical([
                                LogicalCleanupAction::MemoryUnmapped,
                                LogicalCleanupAction::FilenameDropped,
                            ]),
                        )
                    });
                }
                self.absorb_log();
            }
        }
        let carried = self
            .boots
            .get(sandbox)
            .is_some_and(|boot| boot.pump.is_some());
        if carried {
            return;
        }
        let stopped = self.host.as_ref().is_some_and(|host| {
            host.supervisor()
                .coordinator()
                .sandbox(sandbox)
                .is_some_and(|lifecycle| lifecycle.state() == SandboxState::Stopped)
        });
        if !stopped {
            return;
        }
        let torn = self
            .host
            .as_mut()
            .is_some_and(|host| host.session(sandbox).is_none() || host.teardown(sandbox).is_ok());
        if torn {
            if let Some(boot) = self.boots.get_mut(sandbox) {
                boot.torn_down = true;
            }
        }
        self.absorb_log();
    }

    /// Takes `sandbox`'s driver out, to join it without the lock.
    pub(super) fn take_driver(&mut self, sandbox: &ExecutionId) -> Option<JoinHandle<()>> {
        self.boots
            .get_mut(sandbox)
            .and_then(|boot| boot.driver.take())
    }

    /// Puts a driver that did not end within the bound back, for the shutdown to report.
    pub(super) fn put_driver(&mut self, sandbox: &ExecutionId, handle: JoinHandle<()>) {
        if let Some(boot) = self.boots.get_mut(sandbox) {
            boot.driver = Some(handle);
        }
    }

    // ----- status ------------------------------------------------------------------------

    pub(super) fn statuses(&self) -> Vec<SandboxStatus> {
        let Some(host) = self.host.as_ref() else {
            return Vec::new();
        };
        let supervisor = host.supervisor();
        supervisor
            .sandboxes()
            .map(|record| self.status_of(host, record))
            .collect()
    }

    fn status_of(&self, host: &ServiceHost<P>, record: &SandboxRecord) -> SandboxStatus {
        let execution = &record.identity.execution;
        let lifecycle = host.supervisor().coordinator().sandbox(execution);
        let boot = self.boots.get(execution);
        let vm = lifecycle.and_then(SandboxLifecycle::vm);
        let readiness = match &record.readiness {
            ObservedReadiness::AtLaunch => match lifecycle.and_then(SandboxLifecycle::readiness) {
                Some(evidence) => ReadinessView::Ready {
                    observed_at: evidence.observed_at,
                    by: ReadinessBy::Launch,
                },
                None => ReadinessView::NotObserved,
            },
            ObservedReadiness::Ready { at } => ReadinessView::Ready {
                observed_at: *at,
                by: ReadinessBy::Reobservation,
            },
            ObservedReadiness::Unavailable { since, detail } => ReadinessView::Unavailable {
                since: *since,
                detail: detail.clone(),
            },
        };
        let link = match host.session(execution) {
            None => LinkView::NoChannels,
            Some(session) => match session.link().map(HostLink::phase) {
                None => LinkView::ChannelsClosed,
                Some(LinkPhase::AwaitingHello) => LinkView::AwaitingHello,
                Some(LinkPhase::Open) => LinkView::Open,
                Some(LinkPhase::Closed(cause)) => LinkView::Closed {
                    cause: cause.clone(),
                },
            },
        };
        let launch_record =
            vm.and_then(|vm| host.table().record(&vm))
                .map(|launch| LaunchRecordView {
                    identity: launch.identity(),
                    guest_image: launch.pinned().guest_image,
                    configuration: launch.configuration(),
                    accelerator: launch.accelerator().clone(),
                });
        let revocation = host
            .supervisor()
            .revocation(execution)
            .map(|run| RevocationView {
                cause: run.cause(),
                decided_at: run.decided_at(),
                acknowledged: run
                    .acknowledgments()
                    .iter()
                    .map(|(acknowledgment, at)| (*acknowledgment, *at))
                    .collect(),
                pending: run.pending(),
            });
        SandboxStatus {
            sandbox: SandboxId::new(execution.clone()),
            tenant: record.identity.tenant.clone(),
            state: lifecycle.map(SandboxLifecycle::state),
            phase: boot.map(|boot| boot.phase),
            boot: lifecycle.map(|lifecycle| lifecycle.generations().boot),
            vm,
            process: vm.and_then(|vm| host.backend().process_of(&vm)),
            readiness,
            launch_record,
            link,
            transport: boot.map(|boot| TransportView {
                connected: boot.pump.is_some(),
                counters: boot.counters,
                end: boot.transport_end,
            }),
            running_commands: boot
                .map(|boot| {
                    boot.running
                        .keys()
                        .copied()
                        .map(CommandId::from_number)
                        .collect()
                })
                .unwrap_or_default(),
            unclaimed_outcomes: boot.map_or(0, |boot| boot.outcomes.len()),
            egress: EgressView {
                attached: boot.is_some_and(|boot| boot.egress_port.is_some()),
                open_streams: host
                    .session(execution)
                    .map_or(0, BootSession::egress_streams),
            },
            ingress: IngressView {
                open_streams: host
                    .session(execution)
                    .map_or(0, BootSession::ingress_streams),
                requested: boot.map_or(0, |boot| boot.ingress_requests.len()),
                opened: boot.map_or(0, |boot| boot.ingress_opened),
            },
            revocation,
            remote_control: boot
                .and_then(|boot| boot.remote.as_ref())
                .map(|remote| remote.view(host.supervisor().now())),
        }
    }

    // ----- the egress port ---------------------------------------------------------------

    /// Attaches `port` as where `sandbox`'s guest egress streams go; guest opens are accepted
    /// from now on. Refused unless the sandbox is ready.
    pub(super) fn attach_egress(
        &mut self,
        sandbox: &SandboxId,
        port: Box<dyn EgressPort>,
    ) -> Result<(), VmServiceError> {
        self.open()?;
        self.ready_boot(sandbox)?;
        self.authorize_remote(sandbox)?;
        let execution = sandbox.execution();
        let host = self.host.as_mut().ok_or(VmServiceError::ShuttingDown)?;
        host.accept_egress(execution, true)
            .map_err(|error| VmServiceError::of_host(sandbox, error, None))?;
        if let Some(boot) = self.boots.get_mut(execution) {
            boot.egress_port = Some(port);
        }
        Ok(())
    }

    /// Attaches the staged workspace at `root` to `sandbox`'s file channel as the workspace
    /// grant (§5.1 quarantine output): the guest reads and writes beneath `root` and
    /// nowhere else, within `quota`, until `valid_for` passed on the host's clock or the
    /// boot's channels close (a stop or revocation takes every grant off). Refused unless
    /// the sandbox is ready, and when it has a workspace attached already.
    pub(super) fn attach_workspace(
        &mut self,
        sandbox: &SandboxId,
        root: &std::path::Path,
        uploads: Option<&std::path::Path>,
        quota: FileQuota,
        valid_for: Duration,
    ) -> Result<(), VmServiceError> {
        self.attach_files(sandbox, root, uploads, quota, valid_for, None)
    }

    pub(super) fn attach_image(
        &mut self,
        sandbox: &SandboxId,
        root: &std::path::Path,
        quota: FileQuota,
        valid_for: Duration,
        snapshot: crate::foundation::ids::Digest,
    ) -> Result<(), VmServiceError> {
        self.attach_files(sandbox, root, None, quota, valid_for, Some(snapshot))
    }

    fn attach_files(
        &mut self,
        sandbox: &SandboxId,
        root: &std::path::Path,
        uploads: Option<&std::path::Path>,
        quota: FileQuota,
        valid_for: Duration,
        image: Option<crate::foundation::ids::Digest>,
    ) -> Result<(), VmServiceError> {
        self.open()?;
        self.ready_boot(sandbox)?;
        self.authorize_remote(sandbox)?;
        let execution = sandbox.execution();
        let host = self.host.as_mut().ok_or(VmServiceError::ShuttingDown)?;
        let refused = |detail: String| VmServiceError::Workspace { detail };
        let granted = GrantedRoot::open(root)
            .map_err(|error| refused(format!("the staging folder could not be opened: {error}")))?;
        let scope = TrustScope::named(ExecutionCategory::VmSandbox, execution.as_str());
        let clock = host.clock().clone();
        let session = host.registry().session();
        let grant = FileGrant::new(
            granted.handle(),
            image.map_or(GrantMode::QuarantineOutput, |snapshot| {
                GrantMode::ReadOnlySnapshot { snapshot }
            }),
            if image.is_some() {
                [FileOperation::Read, FileOperation::List]
                    .into_iter()
                    .collect()
            } else {
                WORKSPACE_OPERATIONS.into_iter().collect()
            },
            scope.clone(),
            session,
            clock.now().saturating_add(valid_for),
            quota,
        )
        .map_err(|problem| refused(format!("the grant was refused: {problem:?}")))?;
        let mut service = FileService::new(grant, granted)
            .map_err(|refusal| refused(format!("the file service was refused: {refusal:?}")))?;
        // A file of any size moves in ranges and uploads assembled beside the root, never
        // whole in memory (`FileService::with_uploads`).
        if let Some(uploads) = uploads {
            service = service
                .with_uploads(uploads)
                .map_err(|refusal| refused(format!("the upload area was refused: {refusal:?}")))?;
        }
        let dispatcher = FileDispatcher::new(
            service,
            scope,
            clock,
            session,
            channel_limits(&LinkLimits::default()),
        )
        .map_err(|problem| refused(format!("the dispatcher was refused: {problem:?}")))?;
        host.attach_grant(
            execution,
            if image.is_some() {
                GrantHandle(2)
            } else {
                WORKSPACE_GRANT
            },
            dispatcher,
        )
        .map_err(|error| VmServiceError::of_host(sandbox, error, None))
    }

    /// Takes the workspace grant off `sandbox`'s file channel: its streams are cancelled
    /// as revoked. `false` when none was attached or the channels are closed.
    pub(super) fn detach_workspace(&mut self, sandbox: &SandboxId) -> bool {
        self.host.as_mut().is_some_and(|host| {
            host.detach_grant(sandbox.execution(), WORKSPACE_GRANT)
                .is_ok()
        })
    }

    /// Detaches `sandbox`'s egress port: opens are refused again and every open stream is
    /// cancelled, which the port is told. `false` when none was attached.
    pub(super) fn detach_egress(&mut self, sandbox: &SandboxId) -> Result<bool, VmServiceError> {
        let execution = sandbox.execution();
        let Some(boot) = self.boots.get_mut(execution) else {
            return Err(VmServiceError::UnknownSandbox {
                sandbox: sandbox.clone(),
            });
        };
        let Some(mut port) = boot.egress_port.take() else {
            return Ok(false);
        };
        if let Some(host) = self.host.as_mut() {
            if let Ok(events) = host.detach_egress(execution) {
                for event in events {
                    if let EgressEvent::Ended { stream, .. } = event {
                        port.ended(stream);
                    }
                }
            }
        }
        Ok(true)
    }

    /// Moves what the port has for the guest onto the link, and what that produced back to
    /// the port.
    fn pump_egress(&mut self, sandbox: &ExecutionId) {
        let mut taken = Taken::default();
        {
            let Core { host, boots, .. } = self;
            let (Some(host), Some(boot)) = (host.as_mut(), boots.get_mut(sandbox)) else {
                return;
            };
            let Some(port) = boot.egress_port.as_mut() else {
                return;
            };
            let inbound = port.poll_ready(&|stream| {
                host.session(sandbox).map_or(0, |session| session.egress_send_room(stream))
            });
            let mut produced = Vec::new();
            for message in inbound {
                let (stream, result) = match message {
                    EgressInbound::Data { stream, bytes } => {
                        (stream, host.write_egress(sandbox, stream, &bytes))
                    }
                    EgressInbound::End { stream } => (stream, host.end_egress(sandbox, stream)),
                    EgressInbound::Cancel { stream } => {
                        (stream, host.cancel_egress(sandbox, stream))
                    }
                };
                match result {
                    Ok(events) => produced.extend(events),
                    // A write the stream cannot take (pending full, gone) ends it.
                    Err(_) => taken.egress_cancels.push((sandbox.clone(), stream)),
                }
            }
            for event in produced {
                forward_egress(boot, sandbox, event, &mut taken);
            }
        }
        self.settle_taken(taken);
    }

    /// Moves what the gate wrote for `sandbox`'s connection streams onto the link (M14),
    /// credits back what the gate took of them, ends the host's direction of those whose
    /// other end finished, and cancels those the gate closed.
    fn pump_connections(&mut self, sandbox: &ExecutionId) {
        let mut taken = Taken::default();
        {
            let Core { host, boots, .. } = self;
            let (Some(host), Some(boot)) = (host.as_mut(), boots.get_mut(sandbox)) else {
                return;
            };
            if boot.connections.is_empty() {
                return;
            }
            let open: Vec<(u32, Arc<IngressShared>)> = boot
                .connections
                .iter()
                .map(|(number, shared)| (*number, Arc::clone(shared)))
                .collect();
            let mut produced = Vec::new();
            for (number, shared) in open {
                let Some(stream) = StreamId::new(number) else {
                    continue;
                };
                let due = shared.take_credit_due() as u64;
                if due > 0 {
                    if let Ok(events) = host.consume_egress(sandbox, stream, due) {
                        produced.extend(events);
                    }
                }
                let outbound = shared.take_outbound(INGRESS_CHUNK_BYTES);
                if outbound.cancel {
                    taken.egress_cancels.push((sandbox.clone(), stream));
                    continue;
                }
                if outbound.finish {
                    match host.end_egress(sandbox, stream) {
                        Ok(events) => produced.extend(events),
                        Err(_) => taken.egress_cancels.push((sandbox.clone(), stream)),
                    }
                    continue;
                }
                if outbound.bytes.is_empty() {
                    continue;
                }
                match host.write_egress(sandbox, stream, &outbound.bytes) {
                    Ok(events) => produced.extend(events),
                    // The stream's pending bound: the bytes wait for the next pass.
                    Err(HostError::Egress {
                        refusal: EgressRefusal::PendingFull { .. },
                        ..
                    }) => shared.untake(outbound.bytes),
                    Err(_) => taken.egress_cancels.push((sandbox.clone(), stream)),
                }
            }
            for event in produced {
                forward_egress(boot, sandbox, event, &mut taken);
            }
        }
        self.settle_taken(taken);
    }

    // ----- connections -------------------------------------------------------------------

    /// Grants `caller`'s connection endpoint `endpoint` the declared `service` of `callee`
    /// (module docs in `connect`); returns when the grant expires.
    pub(super) fn connect_sandboxes(
        &mut self,
        caller: &SandboxId,
        endpoint: &str,
        callee: &SandboxId,
        service: &str,
        lifetime: Duration,
        budget_bytes: u64,
    ) -> Result<MonotonicTime, VmServiceError> {
        self.open()?;
        self.ready_boot(caller)?;
        self.ready_boot(callee)?;
        self.authorize_remote(caller)?;
        self.authorize_remote(callee)?;
        let Core {
            host, publications, ..
        } = self;
        let host = host.as_ref().ok_or(VmServiceError::ShuttingDown)?;
        publications
            .grant_connection(
                host.supervisor().coordinator(),
                caller.execution(),
                endpoint,
                callee.execution(),
                service,
                lifetime,
                budget_bytes,
            )
            .map_err(|detail| VmServiceError::Connection { detail })
    }

    /// Withdraws what `caller`'s endpoint `endpoint` is granted; returns how many open
    /// connections closed.
    pub(super) fn disconnect(
        &mut self,
        caller: &SandboxId,
        endpoint: &str,
    ) -> Result<usize, VmServiceError> {
        let closed = self
            .publications
            .revoke_connection(caller.execution(), endpoint)
            .map_err(|detail| VmServiceError::Connection { detail })?;
        self.hold_published_channels();
        Ok(closed)
    }

    /// The private directory of `sandbox`'s boot, while the service holds one.
    pub(super) fn private_directory(&self, sandbox: &SandboxId) -> Option<String> {
        self.boots
            .get(sandbox.execution())?
            .directory
            .as_ref()
            .map(|directory| directory.path().as_str().to_owned())
    }

    /// `sandbox`'s connection endpoints, grants and open connections.
    pub(super) fn connections_view(&self, sandbox: &SandboxId) -> super::connect::ConnectionsView {
        match self.host.as_ref() {
            Some(host) => self
                .publications
                .connections_view(host.supervisor().coordinator(), sandbox.execution()),
            None => super::connect::ConnectionsView::default(),
        }
    }

    // ----- publications ------------------------------------------------------------------

    /// Publishes `service` of `sandbox` (module docs in `publish`); returns its identity.
    pub(super) fn publish(
        &mut self,
        sandbox: &SandboxId,
        service: &str,
        audience: super::publish::PublicationAudience,
        lifetime: Duration,
        budget_bytes: u64,
    ) -> Result<(u64, MonotonicTime), VmServiceError> {
        self.open()?;
        self.ready_boot(sandbox)?;
        self.authorize_remote(sandbox)?;
        let Core {
            host, publications, ..
        } = self;
        let host = host.as_ref().ok_or(VmServiceError::ShuttingDown)?;
        let authority = host.supervisor().coordinator();
        let expires_at = crate::sandbox_contract::connections::ConnectionAuthority::now(authority)
            .saturating_add(lifetime);
        publications
            .publish(
                authority,
                sandbox.execution(),
                service,
                audience,
                lifetime,
                budget_bytes,
            )
            .map(|id| (id.get(), expires_at))
            .map_err(|detail| VmServiceError::Ingress { detail })
    }

    /// Withdraws `publication` of `sandbox`; returns how many sessions it closed.
    pub(super) fn withdraw(
        &mut self,
        sandbox: &SandboxId,
        publication: u64,
    ) -> Result<usize, VmServiceError> {
        let id =
            self.publication_id(sandbox, publication)
                .ok_or_else(|| VmServiceError::Ingress {
                    detail: format!("the sandbox has no publication {publication}"),
                })?;
        self.publications
            .withdraw(sandbox.execution(), id)
            .map_err(|detail| VmServiceError::Ingress { detail })
    }

    fn publication_id(
        &self,
        sandbox: &SandboxId,
        publication: u64,
    ) -> Option<crate::sandbox_contract::connections::GatePublicationId> {
        let host = self.host.as_ref()?;
        let authority = host.supervisor().coordinator();
        self.publications
            .gate_ids(authority, sandbox.execution())
            .into_iter()
            .find(|id| id.get() == publication)
    }

    /// What a proof for `publication` of `sandbox` must be bound to, while it stands.
    pub(super) fn proof_binding(
        &self,
        sandbox: &SandboxId,
        publication: u64,
    ) -> Option<crate::sandbox_contract::connections::ProofBinding> {
        let id = self.publication_id(sandbox, publication)?;
        self.publications.proof_binding(sandbox.execution(), id)
    }

    /// Admits a caller of `service` on `sandbox` with `proof`, joining `outside` to a guest
    /// end opened only once admitted; the guest end's room is returned for the caller's side.
    pub(super) fn admit(
        &mut self,
        sandbox: &SandboxId,
        service: &str,
        proof: Option<crate::sandbox_contract::connections::AuthenticationProof>,
        verifier: &dyn crate::sandbox_contract::connections::ProofVerifier,
        mut outside: Box<dyn crate::sandbox_contract::connections::SessionStream>,
        caller_room: Option<super::ingress::CallerRoom>,
    ) -> Result<
        (u64, super::ingress::GuestIngressWatch),
        crate::sandbox_contract::connections::GateRefusal,
    > {
        // A caller learns only that the service is not served on that port.
        let not_served =
            |outside: &mut Box<dyn crate::sandbox_contract::connections::SessionStream>| {
                outside.close();
                super::publish::not_published(service)
            };
        let Some(port) = self.publications.service_port(sandbox.execution(), service) else {
            return Err(not_served(&mut outside));
        };
        let Ok(guest) = self.listener_name(&port).and_then(|listener| {
            self.ingress(sandbox, listener)
                .map_err(|error| error.to_string())
        }) else {
            return Err(not_served(&mut outside));
        };
        let mut guest = guest;
        if let Some(room) = caller_room {
            guest.set_caller_room(room);
        }
        let watch = guest.watch();
        let Core {
            host, publications, ..
        } = self;
        let Some(host) = host.as_ref() else {
            return Err(not_served(&mut outside));
        };
        let admitted = publications
            .admit(
                host.supervisor().coordinator(),
                verifier,
                sandbox.execution(),
                &port,
                proof,
                outside,
                Box::new(guest),
            )
            .map(|session| (session.get(), watch));
        if admitted.is_ok() {
            self.hold_published_channels();
        }
        admitted
    }

    fn listener_name(&self, port: &super::publish::PublishedPort) -> Result<LinkName, String> {
        LinkName::new(port.listener()).map_err(|error| format!("{error:?}"))
    }

    /// Pumps every open session once (module docs in `publish`).
    pub(super) fn pump_sessions(&mut self) -> super::publish::SessionsPumped {
        let pumped = {
            let Core {
                host, publications, ..
            } = self;
            match host.as_ref() {
                Some(host) => publications.pump(host.supervisor().coordinator()),
                None => super::publish::SessionsPumped::default(),
            }
        };
        if !pumped.closed.is_empty() {
            self.hold_published_channels();
        }
        pumped
    }

    /// Tells the host which sandboxes a caller's session holds a channel of (module docs
    /// in `publish`).
    fn hold_published_channels(&mut self) {
        let held = self.publications.holding();
        if let Some(host) = self.host.as_mut() {
            host.hold_channels(held);
        }
    }

    /// `sandbox`'s declared services and publications.
    pub(super) fn publications_view(
        &self,
        sandbox: &SandboxId,
    ) -> super::publish::PublicationsView {
        match self.host.as_ref() {
            Some(host) => self
                .publications
                .view(host.supervisor().coordinator(), sandbox.execution()),
            None => super::publish::PublicationsView::default(),
        }
    }

    // ----- ingress -----------------------------------------------------------------------

    /// A caller's handle on `sandbox`'s guest `listener` (module docs in `ingress`): the
    /// stream opens on the link once the gate first uses the handle. Refused unless the
    /// sandbox is ready, and past [`MAX_INGRESS_STREAMS`].
    pub(super) fn ingress(
        &mut self,
        sandbox: &SandboxId,
        listener: LinkName,
    ) -> Result<GuestIngress, VmServiceError> {
        self.open()?;
        self.ready_boot(sandbox)?;
        self.authorize_remote(sandbox)?;
        let boot = self.boots.get_mut(sandbox.execution()).ok_or_else(|| {
            VmServiceError::UnknownSandbox {
                sandbox: sandbox.clone(),
            }
        })?;
        if boot.ingress_requests.len() + boot.ingress.len() >= MAX_INGRESS_STREAMS {
            return Err(VmServiceError::Ingress {
                detail: format!("the sandbox holds {MAX_INGRESS_STREAMS} ingress streams already"),
            });
        }
        let shared = IngressShared::new(listener);
        boot.ingress_requests.push(Arc::clone(&shared));
        Ok(GuestIngress::new(shared))
    }

    /// Opens the callers' touched requests on the link, hands what callers wrote to it and
    /// cancels the streams whose callers closed (module docs in `ingress`).
    fn pump_ingress(&mut self, sandbox: &ExecutionId) {
        let mut taken = Taken::default();
        {
            let Core { host, boots, .. } = self;
            let (Some(host), Some(boot)) = (host.as_mut(), boots.get_mut(sandbox)) else {
                return;
            };
            if boot.ingress_requests.is_empty() && boot.ingress.is_empty() {
                return;
            }
            let mut produced = Vec::new();
            for shared in std::mem::take(&mut boot.ingress_requests) {
                match shared.request_step() {
                    RequestStep::Wait => boot.ingress_requests.push(shared),
                    RequestStep::Drop => {
                        shared.ended("the caller closed before the stream opened".to_owned());
                    }
                    RequestStep::Open => {
                        match host.open_ingress(sandbox, shared.listener().clone()) {
                            Ok(stream) => {
                                shared.opening(stream);
                                boot.ingress.insert(stream.get(), shared);
                                boot.ingress_opened += 1;
                            }
                            Err(error) => {
                                shared.ended(format!("the stream could not open: {error}"))
                            }
                        }
                    }
                }
            }
            let open: Vec<(u32, Arc<IngressShared>)> = boot
                .ingress
                .iter()
                .map(|(number, shared)| (*number, Arc::clone(shared)))
                .collect();
            for (number, shared) in open {
                let Some(stream) = StreamId::new(number) else {
                    continue;
                };
                let credit = shared.take_credit_due() as u64;
                if credit > 0 {
                    taken.ingress_credit.push((sandbox.clone(), stream, credit));
                }
                let outbound = shared.take_outbound(INGRESS_CHUNK_BYTES);
                if outbound.cancel {
                    taken.ingress_cancels.push((sandbox.clone(), stream));
                    continue;
                }
                if outbound.finish {
                    // The caller is done writing (a sandbox connection's half close).
                    match host.end_ingress(sandbox, stream) {
                        Ok(events) => produced.extend(events),
                        Err(_) => taken.ingress_cancels.push((sandbox.clone(), stream)),
                    }
                    continue;
                }
                if outbound.bytes.is_empty() {
                    continue;
                }
                match host.write_ingress(sandbox, stream, &outbound.bytes) {
                    Ok(events) => produced.extend(events),
                    // The stream's pending bound: the bytes wait for the next pass.
                    Err(crate::sandbox::host::HostError::Ingress {
                        refusal: crate::sandbox::host::IngressRefusal::PendingFull { .. },
                        ..
                    }) => shared.untake(outbound.bytes),
                    Err(_) => taken.ingress_cancels.push((sandbox.clone(), stream)),
                }
            }
            for event in produced {
                forward_ingress(boot, sandbox, event, &mut taken);
            }
        }
        self.settle_taken(taken);
    }

    // ----- shutdown ----------------------------------------------------------------------

    /// Starts the shutdown: no new call is taken and every driver is asked to stop. Returns
    /// the drivers to join, or `None` when the service shut down before.
    pub(super) fn begin_shutdown(&mut self) -> Option<Vec<(ExecutionId, JoinHandle<()>)>> {
        if self.shutting_down || self.host.is_none() {
            return None;
        }
        self.shutting_down = true;
        Some(
            self.boots
                .iter_mut()
                .filter_map(|(execution, boot)| {
                    boot.driver.take().map(|handle| (execution.clone(), handle))
                })
                .collect(),
        )
    }

    /// Closes every channel through the host's shutdown, writes each boot's close frame to
    /// its stream and shuts the stream down, and lists the VMs the backend still holds.
    pub(super) fn close_all(&mut self, bound: Duration) -> ShutdownReport {
        let Some(host) = self.host.take() else {
            return ShutdownReport::default();
        };
        let HostShutdown { parts, log } = host.shut_down();
        let deadline = deadline_after(bound);
        let mut closed = Vec::new();
        for closure in log.closures {
            let Some(boot) = self.boots.get_mut(&closure.execution) else {
                continue;
            };
            // The supervisor is gone: no lease is given back and no first command marked.
            let mut taken = Taken::default();
            for result in closure.commands {
                take_result(boot, &closure.execution, result, &mut taken, true);
            }
            let close_frame_written = match boot.pump.take() {
                Some(pump) => write_final(pump.into_transport(), &closure.final_frames, deadline),
                None => false,
            };
            boot.phase = BootPhase::Ended;
            closed.push(ChannelsClosedOnShutdown {
                sandbox: SandboxId::new(closure.execution.clone()),
                close_frame_written,
                commands_ended: std::mem::take(&mut boot.ended_by_closure),
            });
        }
        for boot in self.boots.values_mut() {
            boot.pump = None;
        }
        let running: BTreeSet<VmInstanceId> = parts.backend.running().into_iter().collect();
        let vms_left_running = self
            .boots
            .iter()
            .filter(|(_, boot)| boot.vm.is_some_and(|vm| running.contains(&vm)))
            .map(|(execution, _)| SandboxId::new(execution.clone()))
            .collect();
        ShutdownReport {
            closed,
            drivers_joined: 0,
            drivers_not_joined: Vec::new(),
            vms_left_running,
        }
    }
}

/// Asks one authorization of `sandbox`'s revoked boot so its refusal is the observed denial
/// of new work (the revocation's "new authorizations denied"); a lease issued all the same
/// is given back at once.
fn observe_denial<P: VmPorts>(host: &mut ServiceHost<P>, sandbox: &ExecutionId) {
    let asked = host.authorize_work(
        sandbox,
        OperationId::generate(),
        LeaseKind::ChildWork,
        PROBE_CALL,
        BTreeSet::new(),
    );
    if let Ok(lease) = asked {
        // Never issued under a revocation; given back at once all the same.
        host.with_supervisor(|supervisor, _, _| {
            let _ = supervisor.coordinator_mut().release_lease(lease.id());
        });
    }
}
