//! The host (module docs in `mod.rs`): the supervisor, the backend behind integration's
//! port, the audit sink and the boot sessions, with the routes between them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use crate::foundation::coordination::{
    CapacityPort, Lease, LeaseKind, RecoveryFailure, SandboxState,
};
use crate::foundation::events::{AuditReceipt, AuditSpool, Field, HostFact, Phase};
use crate::foundation::evidence::{AdmittedRuntime, ClockSession, ProbeRegistry};
use crate::foundation::ids::{Clock, Digest, ExecutionId, GrantId, OperationId};
use crate::sandbox::audit::{HeadAnchor, SegmentStorage};
use crate::sandbox::backend::VmBackend as ContractBackend;
use crate::sandbox::guest_files::FilesEvent;
use crate::sandbox::integration::{
    AuditSink, LaunchProfile, LaunchTable, ReservationResolver, SinkRefusal,
};
use crate::sandbox::lifecycle::{
    Acknowledgment, CallTerms, LaunchReceipt, LaunchRequest, ObservedReadiness,
    PersistedSupervisor, RevocationCause, RevocationProgress, Supervisor, SupervisorConfig,
    SupervisorRecovery, TickReport, VmBackend as LifecycleBackend,
};
use crate::sandbox::link::{
    BootstrapSecret, ConnectionNonce, GrantHandle, HostLink, LinkBinding, LinkName, StreamId,
};
use crate::sandbox_contract::file_protocol::FileDispatcher;

use super::error::HostError;
use super::egress::EgressEvent;
use super::ingress::IngressEvent;
use super::log::{
    ChannelsAcknowledged, ClosureCause, Delivery, HostLog, HostTick, RevocationAdvanced,
    TeardownReport,
};
use super::session::{BootSession, ChannelSetup, TransportState};
use super::terminal::{CommandRequest, CommandResult};
use crate::sandbox::link_transport::TransportEnd;

/// The lifecycle's backend port over `parts`, for one supervisor call: integration's
/// `BackendPort` over the launch table, the backend, the registry and the resolver.
macro_rules! port {
    ($parts:expr) => {
        $parts
            .table
            .port(&mut $parts.backend, &$parts.registry, &$parts.reservations)
    };
}

/// What a host is made of besides its supervisor and its boot sessions: the parts that
/// outlive a restart of the supervisor. The backend's VMs run on, the launch table keeps
/// the records the backend sealed, the registry its CORE-01 evidence, and the audit sink
/// its stream (a durable sink is released and opened again across a process restart).
pub struct HostParts<C: Clock + Clone, B, R, S, Q, A> {
    pub clock: C,
    pub registry: ProbeRegistry<C>,
    pub backend: B,
    pub table: LaunchTable,
    pub reservations: R,
    pub sink: AuditSink<S, Q, A, C>,
    /// The identities of the launch records already given to the sink, so a record is
    /// given once, across a restart of the supervisor too.
    pub audited: BTreeSet<Digest>,
}

impl<C: Clock + Clone, B, R, S, Q, A> HostParts<C, B, R, S, Q, A> {
    /// The parts of a new host, no launch record given to the sink yet.
    pub fn new(
        clock: C,
        registry: ProbeRegistry<C>,
        backend: B,
        table: LaunchTable,
        reservations: R,
        sink: AuditSink<S, Q, A, C>,
    ) -> Self {
        Self {
            clock,
            registry,
            backend,
            table,
            reservations,
            sink,
            audited: BTreeSet::new(),
        }
    }
}

/// A host that shut down: its parts, and what it recorded last, the closure of every
/// channel it held included.
pub struct HostShutdown<C: Clock + Clone, B, R, S, Q, A> {
    pub parts: HostParts<C, B, R, S, Q, A>,
    pub log: HostLog,
}

/// A recovery that could not finish: the supervisor's failure, with its capacity port,
/// and the parts handed back so recovery can be tried again.
pub struct HostRecoveryFailure<C: Clock + Clone, B, R, S, Q, A, P> {
    pub failure: RecoveryFailure<P>,
    pub parts: HostParts<C, B, R, S, Q, A>,
}

impl<C: Clock + Clone, B, R, S, Q, A, P> fmt::Debug for HostRecoveryFailure<C, B, R, S, Q, A, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostRecoveryFailure")
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl<C: Clock + Clone, B, R, S, Q, A, P> fmt::Display for HostRecoveryFailure<C, B, R, S, Q, A, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.failure, f)
    }
}

impl<C: Clock + Clone, B, R, S, Q, A, P> std::error::Error
    for HostRecoveryFailure<C, B, R, S, Q, A, P>
{
}

/// The sandbox host: the supervisor, the backend, the audit sink and, per sandbox boot,
/// the handle, link and file channel, with the routes between them.
pub struct SandboxHost<C, P, B, R, S, Q, A>
where
    C: Clock + Clone,
    P: CapacityPort,
{
    supervisor: Supervisor<C, P>,
    parts: HostParts<C, B, R, S, Q, A>,
    sessions: BTreeMap<ExecutionId, BootSession<C>>,
    log: HostLog,
    /// Sandboxes a connection gate serves a caller of now: their channels are not closed in
    /// fact while it does ([`SandboxHost::hold_channels`]).
    held_channels: std::collections::BTreeSet<ExecutionId>,
}

impl<C, P, B, R, S, Q, A> SandboxHost<C, P, B, R, S, Q, A>
where
    C: Clock + Clone,
    P: CapacityPort,
    B: ContractBackend,
    R: ReservationResolver,
    S: SegmentStorage,
    Q: AuditSpool,
    A: HeadAnchor,
{
    /// A host over `parts` with a new supervisor on the parts' clock, in `session`, over
    /// `capacity`.
    pub fn new(
        parts: HostParts<C, B, R, S, Q, A>,
        session: ClockSession,
        capacity: P,
        config: SupervisorConfig,
    ) -> Self {
        let supervisor = Supervisor::new(parts.clock.clone(), session, capacity, config);
        Self {
            supervisor,
            parts,
            sessions: BTreeMap::new(),
            log: HostLog::default(),
            held_channels: std::collections::BTreeSet::new(),
        }
    }

    /// Restarts the supervisor from `persisted` over `parts` (§6.1 line 2292; VM-D7):
    /// every stored handle is checked through the backend, no lease or authority is
    /// revived, a task found alive is ended through its handle, and a service is kept
    /// without authority until [`SandboxHost::reauthorize`]. The new host holds no channel;
    /// what recovery did reaches the audit sink as the supervisor recorded it. `session` is
    /// the clock session after the restart. A failure hands the parts back, boxed.
    #[allow(clippy::type_complexity)]
    pub fn recover(
        mut parts: HostParts<C, B, R, S, Q, A>,
        persisted: PersistedSupervisor,
        session: ClockSession,
        capacity: P,
        config: SupervisorConfig,
    ) -> Result<(Self, SupervisorRecovery), Box<HostRecoveryFailure<C, B, R, S, Q, A, P>>> {
        let clock = parts.clock.clone();
        let recovered = {
            let mut port = port!(parts);
            Supervisor::recover(persisted, clock, session, capacity, config, &mut port)
        };
        match recovered {
            Ok((supervisor, report)) => {
                let mut host = Self {
                    supervisor,
                    parts,
                    sessions: BTreeMap::new(),
                    log: HostLog::default(),
                    held_channels: std::collections::BTreeSet::new(),
                };
                host.settle();
                Ok((host, report))
            }
            Err(failure) => Err(Box::new(HostRecoveryFailure { failure, parts })),
        }
    }

    /// Closes every boot's channels for shutting down and hands back the parts. The
    /// supervisor is dropped; persist it first ([`SandboxHost::persist`]).
    pub fn shut_down(mut self) -> HostShutdown<C, B, R, S, Q, A> {
        let now = self.parts.clock.now();
        for session in self.sessions.values_mut() {
            if session.is_open() {
                let closure = session.close(ClosureCause::Shutdown, now);
                self.log.closures.push(closure);
            }
        }
        HostShutdown {
            parts: self.parts,
            log: self.log,
        }
    }

    pub fn supervisor(&self) -> &Supervisor<C, P> {
        &self.supervisor
    }

    pub fn clock(&self) -> &C {
        &self.parts.clock
    }

    pub fn registry(&self) -> &ProbeRegistry<C> {
        &self.parts.registry
    }

    /// The host's CORE-01 registry, for its probes to refresh evidence.
    pub fn registry_mut(&mut self) -> &mut ProbeRegistry<C> {
        &mut self.parts.registry
    }

    pub fn backend(&self) -> &B {
        &self.parts.backend
    }

    /// The backend itself, for what the lifecycle does not do (a backend's own settings).
    /// Launching, stopping or restoring through it bypasses the lifecycle; do that through
    /// the host.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.parts.backend
    }

    pub fn table(&self) -> &LaunchTable {
        &self.parts.table
    }

    pub fn sink(&self) -> &AuditSink<S, Q, A, C> {
        &self.parts.sink
    }

    /// Gives the audit sink a host fact about `execution` while it runs (the engine's
    /// response path: a monitoring signal, a response decision).
    pub fn record_running_fact(
        &mut self,
        execution: &ExecutionId,
        fact: HostFact,
        fields: Vec<Field>,
    ) -> Result<AuditReceipt, SinkRefusal> {
        self.parts.sink.record_running_fact(execution, fact, fields)
    }

    /// Gives the audit sink a host fact about `execution` at `phase`.
    pub fn record_fact(
        &mut self,
        execution: &ExecutionId,
        phase: Phase,
        fact: HostFact,
        fields: Vec<Field>,
    ) -> Result<AuditReceipt, SinkRefusal> {
        self.parts.sink.record_fact(execution, phase, fact, fields)
    }

    /// The boot session of `execution`, open or closed, until its teardown.
    pub fn session(&self, execution: &ExecutionId) -> Option<&BootSession<C>> {
        self.sessions.get(execution)
    }

    pub fn sessions(&self) -> impl Iterator<Item = &BootSession<C>> {
        self.sessions.values()
    }

    /// Takes what the host recorded since the last take: what reached the audit sink and
    /// how, the channels it closed and the acknowledgments it gave.
    pub fn take_log(&mut self) -> HostLog {
        std::mem::take(&mut self.log)
    }

    /// Sets the launch profile every boot of `execution` launches under.
    pub fn set_profile(&mut self, execution: ExecutionId, profile: LaunchProfile) {
        self.parts.table.set_profile(execution, profile);
    }

    /// What to persist; store it durably, then [`SandboxHost::confirm_persisted`].
    pub fn persist(&self) -> PersistedSupervisor {
        self.supervisor.persist()
    }

    pub fn confirm_persisted(&mut self, state: &PersistedSupervisor) {
        self.supervisor.confirm_persisted(state);
    }

    /// Launches a sandbox cold through the supervisor (§6.1): authority only after
    /// host-observed readiness, nothing exposed by a failed start. Its channels open
    /// afterwards ([`SandboxHost::open_channels`]).
    pub fn launch(&mut self, request: LaunchRequest) -> Result<LaunchReceipt, HostError> {
        let launched = {
            let mut port = port!(self.parts);
            self.supervisor
                .launch(request, &mut port, &self.parts.registry)
        };
        self.settle();
        Ok(launched?)
    }

    /// Grants authority again to a service recovery kept without it, after fresh readiness
    /// and evidence checks; its channels open afterwards, as after a launch.
    pub fn reauthorize(
        &mut self,
        execution: &ExecutionId,
        runtime: AdmittedRuntime,
    ) -> Result<LaunchReceipt, HostError> {
        let receipt = {
            let mut port = port!(self.parts);
            self.supervisor
                .reauthorize(execution, runtime, &mut port, &self.parts.registry)
        };
        self.settle();
        Ok(receipt?)
    }

    /// Opens the channels of `execution`'s current boot: refused unless the boot holds
    /// authority and the supervisor keeps the handle of its VM. The link is bound to that
    /// VM instance and boot generation with `setup.secret` and to the connection nonce
    /// `setup.connection`, its challenge queued first; the file channel's identity is
    /// the boot's and the sandbox's tenant and execution, and every grant of `setup` is
    /// attached, or nothing opens. A boot's channels open once; a closed session of an
    /// earlier boot is replaced.
    pub fn open_channels(
        &mut self,
        execution: &ExecutionId,
        setup: ChannelSetup<C>,
    ) -> Result<(), HostError> {
        let sandbox = self
            .supervisor
            .coordinator()
            .sandbox(execution)
            .ok_or_else(|| HostError::UnknownSandbox {
                execution: execution.clone(),
            })?;
        let state = sandbox.state();
        if !state.holds_authority() {
            return Err(HostError::NoAuthority {
                execution: execution.clone(),
                state,
            });
        }
        let boot = sandbox.generations().boot;
        let tenant = sandbox.tenant().clone();
        let handle = sandbox
            .vm()
            .and_then(|vm| self.supervisor.handles().get(&vm))
            .filter(|handle| handle.boot == boot && &handle.execution == execution)
            .cloned()
            .ok_or_else(|| HostError::NoHandle {
                execution: execution.clone(),
                boot,
            })?;
        if let Some(existing) = self.sessions.get(execution) {
            if existing.is_open() {
                return Err(HostError::ChannelsOpen {
                    execution: execution.clone(),
                    boot: existing.boot(),
                });
            }
            if existing.boot() == boot {
                return Err(HostError::ChannelsClosed {
                    execution: execution.clone(),
                    boot,
                });
            }
        }
        let session = BootSession::open(
            execution.clone(),
            handle,
            tenant,
            self.parts.clock.clone(),
            setup,
        )?;
        self.sessions.insert(execution.clone(), session);
        Ok(())
    }

    /// Replaces the closed link of `execution`'s boot with a new one bound to the same VM
    /// instance and boot generation and to `connection`, the nonce drawn for the new
    /// connection with `ConnectionNonce::draw`, as after the transport reconnected: refused
    /// while the link is open, once the host closed the boot's channels, unless the boot
    /// holds authority, and for a nonce a link of the boot used already. The
    /// new link's challenge goes out first, and frames of the earlier connection are
    /// refused on it (M06-LC). The file channel follows the new link, and a body the old
    /// one interrupted resumes on it; a command the old link carried has ended.
    pub fn reconnect(
        &mut self,
        execution: &ExecutionId,
        secret: BootstrapSecret,
        connection: ConnectionNonce,
    ) -> Result<(), HostError> {
        self.enforce()?;
        let clock = self.parts.clock.clone();
        let now = clock.now();
        let session = self.open_session(execution)?;
        if session.used_connection(connection.connection()) {
            return Err(HostError::ConnectionReused {
                execution: execution.clone(),
                boot: session.boot(),
            });
        }
        let link = HostLink::connect(
            LinkBinding::new(session.vm(), session.boot(), secret),
            connection,
            session.link_limits(),
            clock,
        )
        .map_err(HostError::Link)?;
        session.replace_link(link, now)
    }

    /// Attaches `grant` to `execution`'s open file channel.
    pub fn attach_grant(
        &mut self,
        execution: &ExecutionId,
        grant: GrantHandle,
        dispatcher: FileDispatcher<C>,
    ) -> Result<(), HostError> {
        let session = self.open_session(execution)?;
        session
            .files_mut()
            .add_grant(grant, dispatcher)
            .map_err(|refused| HostError::Grant {
                grant,
                error: refused.error,
            })
    }

    /// Takes `grant` off `execution`'s file channel: its streams are cancelled as revoked
    /// on the link, its bodies end, and its dispatcher is dropped.
    pub fn detach_grant(
        &mut self,
        execution: &ExecutionId,
        grant: GrantHandle,
    ) -> Result<Vec<FilesEvent>, HostError> {
        let session = self.open_session(execution)?;
        let removed = session
            .files_mut()
            .remove_grant(grant)
            .ok_or(HostError::UnknownGrant { grant })?;
        let mut events = removed.events;
        let (link, files) = session.parts_mut()?;
        events.extend(files.pump(link).map_err(HostError::Mismatch)?);
        Ok(events)
    }

    /// Delivers bytes the transport read from `execution`'s guest. The sandbox leases are
    /// enforced first, at the clock's reading, and a boot that no longer holds authority
    /// has its channels closed before anything is routed. The file channel's events go to
    /// the adapter; while the host did not find the VM ready, a new file stream is refused
    /// before it.
    pub fn receive(
        &mut self,
        execution: &ExecutionId,
        bytes: &[u8],
    ) -> Result<Delivery, HostError> {
        self.enforce()?;
        let refuse_opens = self.readiness_unavailable(execution);
        let now = self.parts.clock.now();
        let session = self.session_mut(execution)?;
        let (link, _) = session.parts_mut()?;
        let events = link.receive(bytes);
        session.route(events, refuse_opens, now)
    }

    /// The transport reports `execution`'s guest gone: the link closes, the file channel
    /// interrupts what moved on it, and the running commands end.
    pub fn peer_closed(&mut self, execution: &ExecutionId) -> Result<Delivery, HostError> {
        let now = self.parts.clock.now();
        let session = self.session_mut(execution)?;
        let (link, _) = session.parts_mut()?;
        let events = link.peer_closed();
        session.route(events, false, now)
    }

    /// Lets the file channel send what the link takes now and take guest messages it held
    /// back.
    pub fn pump(&mut self, execution: &ExecutionId) -> Result<Vec<FilesEvent>, HostError> {
        let session = self.session_mut(execution)?;
        let (link, files) = session.parts_mut()?;
        files.pump(link).map_err(HostError::Mismatch)
    }

    /// The next frame for `execution`'s transport, sealed, taken only when the transport
    /// can write it now (the session pump's way, which keeps revocation ahead of bulk
    /// frames queued later): the link's, in the order of [`SandboxHost::outbound`], or,
    /// once the host closed the boot's channels, the frames the link left (its close
    /// frame). `None` when nothing waits.
    pub fn next_outbound(&mut self, execution: &ExecutionId) -> Result<Option<Vec<u8>>, HostError> {
        Ok(self.session_mut(execution)?.next_outbound())
    }

    /// Starts a command in `execution`'s guest (the terminal command path): the sandbox
    /// leases are enforced first and the boot must hold authority, its channels open and
    /// its link past the handshake. A terminal stream opens on the link; the request's
    /// input goes out as the guest grants credit and is then ended; the guest's output and
    /// exit report come back in the deliveries' commands
    /// ([`CommandEvent`](super::CommandEvent)). Returns the command's stream.
    pub fn start_command(
        &mut self,
        execution: &ExecutionId,
        request: CommandRequest,
    ) -> Result<StreamId, HostError> {
        self.enforce()?;
        let now = self.parts.clock.now();
        self.open_session(execution)?.start_command(request, now)
    }

    /// Whether `execution`'s boot accepts guest egress opens: a port is attached (the
    /// relay's guest transport) or not. Opens while no port is attached are refused.
    pub fn accept_egress(&mut self, execution: &ExecutionId, accepting: bool) -> Result<(), HostError> {
        self.enforce()?;
        self.open_session(execution)?.set_egress_accepting(accepting);
        Ok(())
    }

    /// `execution`'s sandbox connection endpoints (M14): guest egress opens naming one are
    /// accepted whether or not a port is attached, and credited back as consumed
    /// ([`SandboxHost::consume_egress`]).
    pub fn accept_connections(
        &mut self,
        execution: &ExecutionId,
        names: BTreeSet<LinkName>,
    ) -> Result<(), HostError> {
        self.enforce()?;
        self.open_session(execution)?.set_egress_connections(names);
        Ok(())
    }

    /// `bytes` of a sandbox connection's egress `stream` were taken by its other end: their
    /// credit goes back to the guest. The egress events that produced are returned.
    pub fn consume_egress(
        &mut self,
        execution: &ExecutionId,
        stream: StreamId,
        bytes: u64,
    ) -> Result<Vec<EgressEvent>, HostError> {
        self.enforce()?;
        Ok(self.open_session(execution)?.consume_egress(stream, bytes))
    }

    /// Writes the port's `bytes` to the guest on egress `stream`; the egress events that
    /// produced are returned.
    pub fn write_egress(
        &mut self,
        execution: &ExecutionId,
        stream: StreamId,
        bytes: &[u8],
    ) -> Result<Vec<EgressEvent>, HostError> {
        self.enforce()?;
        self.open_session(execution)?.write_egress(stream, bytes)
    }

    /// Ends the host's direction of egress `stream`.
    pub fn end_egress(
        &mut self,
        execution: &ExecutionId,
        stream: StreamId,
    ) -> Result<Vec<EgressEvent>, HostError> {
        self.enforce()?;
        self.open_session(execution)?.end_egress(stream)
    }

    /// Detaches `execution`'s egress port: opens are refused again and every open egress
    /// stream is cancelled; the events are returned.
    pub fn detach_egress(&mut self, execution: &ExecutionId) -> Result<Vec<EgressEvent>, HostError> {
        self.enforce()?;
        self.open_session(execution)?.detach_egress()
    }

    /// Cancels egress `stream`: the port's side failed.
    pub fn cancel_egress(
        &mut self,
        execution: &ExecutionId,
        stream: StreamId,
    ) -> Result<Vec<EgressEvent>, HostError> {
        self.enforce()?;
        self.open_session(execution)?.cancel_egress(stream)
    }

    /// Opens an ingress stream to `execution`'s guest `listener` (M14: a caller the
    /// connection gate admitted), after the same checks as [`SandboxHost::start_command`];
    /// the guest's answer comes in a later delivery.
    pub fn open_ingress(
        &mut self,
        execution: &ExecutionId,
        listener: LinkName,
    ) -> Result<StreamId, HostError> {
        self.enforce()?;
        self.open_session(execution)?.open_ingress(listener)
    }

    /// Writes the caller's `bytes` to the guest on ingress `stream`; the ingress events
    /// that produced are returned.
    pub fn write_ingress(
        &mut self,
        execution: &ExecutionId,
        stream: StreamId,
        bytes: &[u8],
    ) -> Result<Vec<IngressEvent>, HostError> {
        self.enforce()?;
        self.open_session(execution)?.write_ingress(stream, bytes)
    }

    /// Ends the host's direction of ingress `stream`.
    pub fn end_ingress(
        &mut self,
        execution: &ExecutionId,
        stream: StreamId,
    ) -> Result<Vec<IngressEvent>, HostError> {
        self.enforce()?;
        self.open_session(execution)?.end_ingress(stream)
    }

    /// `bytes` of `execution`'s guest data on ingress `stream` were taken by its caller:
    /// their credit goes back to the stream.
    pub fn consume_ingress(
        &mut self,
        execution: &ExecutionId,
        stream: StreamId,
        bytes: u64,
    ) -> Result<Vec<IngressEvent>, HostError> {
        self.enforce()?;
        Ok(self.open_session(execution)?.consume_ingress(stream, bytes))
    }

    /// Cancels ingress `stream`: its caller went away or was closed.
    pub fn cancel_ingress(
        &mut self,
        execution: &ExecutionId,
        stream: StreamId,
    ) -> Result<Vec<IngressEvent>, HostError> {
        self.enforce()?;
        self.open_session(execution)?.cancel_ingress(stream)
    }

    /// Names the sandboxes a connection gate serves a caller of now (M14): their channels
    /// are not closed in fact while it does, so "channels closed" waits for the gate.
    pub fn hold_channels(&mut self, held: std::collections::BTreeSet<ExecutionId>) {
        self.held_channels = held;
    }

    /// Asks `execution`'s guest to shut down within `grace` (the link's `Shutdown` message,
    /// sent urgently), after the same checks as [`SandboxHost::start_command`]. The guest
    /// that complies powers off: the host observes that as its stream ending and, through
    /// the backend, as the VM's process ending; this request proves neither. A stop then
    /// revokes the sandbox, which stops a VM still running through its handle.
    pub fn request_shutdown(
        &mut self,
        execution: &ExecutionId,
        grace: Duration,
    ) -> Result<(), HostError> {
        self.enforce()?;
        self.open_session(execution)?.request_shutdown(grace)
    }

    /// A transport takes `execution`'s boot's link (the session pump, made over the boot's
    /// checked stream): from now on "channels closed" is acknowledged for the boot only once
    /// that stream ended ([`SandboxHost::transport_ended`]). Refused while another
    /// transport carries it, or without channels.
    pub fn attach_transport(&mut self, execution: &ExecutionId) -> Result<(), HostError> {
        self.session_mut(execution)?.attach_transport()
    }

    /// The transport carrying `execution`'s boot's link ended as `end` says (the pump shut
    /// the stream down, or its owner dropped it): the physical closure of the boot's
    /// channels. For a sandbox under revocation with no channel left open, "channels
    /// closed" is acknowledged now and the revocation advanced.
    pub fn transport_ended(
        &mut self,
        execution: &ExecutionId,
        end: TransportEnd,
    ) -> Result<(), HostError> {
        self.session_mut(execution)?.transport_ended(end)?;
        self.settle();
        Ok(())
    }

    /// Cancels the command on `stream` of `execution`'s boot, after the same checks as
    /// [`SandboxHost::start_command`]: the stream is cancelled on the link and the command
    /// ends with the output so far. A command of a boot whose channels the host closed
    /// has ended already, in that closure.
    pub fn cancel_command(
        &mut self,
        execution: &ExecutionId,
        stream: StreamId,
    ) -> Result<CommandResult, HostError> {
        self.enforce()?;
        let now = self.parts.clock.now();
        self.open_session(execution)?.cancel_command(stream, now)
    }

    /// The frames `execution`'s link has for the transport, sealed, in order: the urgent
    /// ones first, then control, then the bulk channels in turn.
    pub fn outbound(&mut self, execution: &ExecutionId) -> Result<Vec<Vec<u8>>, HostError> {
        let session = self.session_mut(execution)?;
        let (link, _) = session.parts_mut()?;
        let mut frames = Vec::new();
        while let Some(frame) = link.next_outbound() {
            frames.push(frame);
        }
        Ok(frames)
    }

    /// One tick: the supervisor enforces every sandbox lease (an expired limit or a clock
    /// rolled back revokes, and the host closes that boot's channels), every revocation
    /// whose VM has not stopped is advanced, then each open boot's link applies its
    /// timeouts, its commands past their time limit are cancelled, and its file channel
    /// checks its bodies' transfers for revocation and expiry.
    pub fn tick(&mut self) -> Result<HostTick, HostError> {
        let supervisor = self.enforce()?;
        let stopping: Vec<ExecutionId> = self
            .supervisor
            .sandboxes()
            .map(|record| record.identity.execution.clone())
            .filter(|execution| {
                self.supervisor
                    .revocation(execution)
                    .is_some_and(|run| run.acknowledged_at(Acknowledgment::VmStopped).is_none())
            })
            .collect();
        for execution in &stopping {
            self.advance_revocation(execution);
        }
        self.settle();
        let now = self.parts.clock.now();
        let mut deliveries = Vec::new();
        for (execution, session) in &mut self.sessions {
            if !session.is_open() {
                continue;
            }
            let events = match session.parts_mut() {
                Ok((link, _)) => link.tick(),
                Err(_) => continue,
            };
            let mut delivery = session.route(events, false, now)?;
            delivery.files.extend(session.files_mut().tick());
            let (link, files) = session.parts_mut()?;
            delivery
                .files
                .extend(files.pump(link).map_err(HostError::Mismatch)?);
            deliveries.push((execution.clone(), delivery));
        }
        Ok(HostTick {
            supervisor,
            deliveries,
        })
    }

    /// Asks the backend, through the port, to observe `execution`'s VM again now.
    pub fn observe_readiness(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<ObservedReadiness, HostError> {
        let observed = {
            let mut port = port!(self.parts);
            self.supervisor.observe_readiness(execution, &mut port)
        };
        self.settle();
        Ok(observed?)
    }

    /// Authorizes child work under `grants` of the sandbox's authority on fresh readiness
    /// (`Supervisor::authorize_observed_work`): when the last readiness is older than the
    /// configured age, the backend observes the VM again first, and while the host does
    /// not find it ready nothing is authorized.
    pub fn authorize_work(
        &mut self,
        execution: &ExecutionId,
        operation: OperationId,
        kind: LeaseKind,
        call: CallTerms,
        grants: BTreeSet<GrantId>,
    ) -> Result<Lease, HostError> {
        let lease = {
            let mut port = port!(self.parts);
            self.supervisor
                .authorize_observed_work(execution, operation, kind, call, grants, &mut port)
        };
        self.settle();
        Ok(lease?)
    }

    /// The first successful command in the guest (the BENCH-05 clock stops): accepted only
    /// once the current boot's link completed its handshake, since a guest command runs
    /// over it.
    pub fn first_command(&mut self, execution: &ExecutionId) -> Result<Duration, HostError> {
        let boot = self
            .supervisor
            .coordinator()
            .sandbox(execution)
            .map(|sandbox| sandbox.generations().boot);
        let linked = self
            .sessions
            .get(execution)
            .is_some_and(|session| Some(session.boot()) == boot && session.link_is_open());
        if !linked {
            return Err(HostError::LinkNotOpen {
                execution: execution.clone(),
            });
        }
        let elapsed = self.supervisor.first_command(execution);
        self.settle();
        Ok(elapsed?)
    }

    /// Revokes the sandbox (§6.3): the supervisor advances the durable epoch and cancels
    /// every lease; the host closes the boot's channels, acknowledges "channels closed" and
    /// advances the revocation as far as the policy and the outstanding leases allow,
    /// stopping the VM through its handle once they do. Returns where it stands.
    pub fn revoke(
        &mut self,
        execution: &ExecutionId,
        cause: RevocationCause,
    ) -> Result<RevocationProgress, HostError> {
        let revoked = {
            let mut port = port!(self.parts);
            self.supervisor.revoke(execution, cause, &mut port)
        };
        self.settle();
        revoked?;
        self.advance(execution)
    }

    /// Advances a revocation (§6.3 steps 3–5): once the gate opens, the VM is stopped
    /// through its handle and the bounded cleanup starts.
    pub fn advance(&mut self, execution: &ExecutionId) -> Result<RevocationProgress, HostError> {
        let progress = {
            let mut port = port!(self.parts);
            self.supervisor.advance(execution, &mut port)
        };
        self.settle();
        Ok(progress?)
    }

    /// Any other supervisor call, with the backend port and the registry: activity, lease
    /// acknowledgments, provider acknowledgments, cleanup, grant revocations, the engine's
    /// death, violations, renewals, checkouts. Afterwards the host closes the channels of
    /// every boot that lost authority and gives the sink what the call recorded, as after
    /// its own calls.
    pub fn with_supervisor<T>(
        &mut self,
        call: impl FnOnce(&mut Supervisor<C, P>, &mut dyn LifecycleBackend, &ProbeRegistry<C>) -> T,
    ) -> T {
        let value = {
            let mut port = port!(self.parts);
            call(&mut self.supervisor, &mut port, &self.parts.registry)
        };
        self.settle();
        value
    }

    /// Tears down `execution`'s boot once its VM stopped: its session is dropped, with the
    /// file channel's counters reported.
    pub fn teardown(&mut self, execution: &ExecutionId) -> Result<TeardownReport, HostError> {
        let state = self
            .supervisor
            .coordinator()
            .sandbox(execution)
            .map(|sandbox| sandbox.state())
            .ok_or_else(|| HostError::UnknownSandbox {
                execution: execution.clone(),
            })?;
        if state != SandboxState::Stopped {
            return Err(HostError::NotStopped {
                execution: execution.clone(),
                state,
            });
        }
        let mut session = self
            .sessions
            .remove(execution)
            .ok_or_else(|| HostError::NoChannels {
                execution: execution.clone(),
            })?;
        if session.is_open() {
            let closure = session.close(
                ClosureCause::AuthorityLost { state: Some(state) },
                self.parts.clock.now(),
            );
            self.log.closures.push(closure);
        }
        Ok(TeardownReport {
            execution: execution.clone(),
            boot: session.boot(),
            vm: session.vm(),
            counters: session.files().counters(),
            closed_at: session.closed_at(),
        })
    }

    fn session_mut(&mut self, execution: &ExecutionId) -> Result<&mut BootSession<C>, HostError> {
        self.sessions
            .get_mut(execution)
            .ok_or_else(|| HostError::NoChannels {
                execution: execution.clone(),
            })
    }

    /// The session of `execution` whose channels the host has not closed, while its boot
    /// holds authority.
    fn open_session(&mut self, execution: &ExecutionId) -> Result<&mut BootSession<C>, HostError> {
        let sandbox = self
            .supervisor
            .coordinator()
            .sandbox(execution)
            .ok_or_else(|| HostError::UnknownSandbox {
                execution: execution.clone(),
            })?;
        let (state, boot) = (sandbox.state(), sandbox.generations().boot);
        let session = self
            .sessions
            .get_mut(execution)
            .ok_or_else(|| HostError::NoChannels {
                execution: execution.clone(),
            })?;
        if !session.is_open() {
            return Err(HostError::ChannelsClosed {
                execution: execution.clone(),
                boot: session.boot(),
            });
        }
        if !state.holds_authority() || session.boot() != boot {
            return Err(HostError::NoAuthority {
                execution: execution.clone(),
                state,
            });
        }
        Ok(session)
    }

    /// Whether the host last found `execution`'s VM not ready.
    fn readiness_unavailable(&self, execution: &ExecutionId) -> bool {
        self.supervisor
            .sandbox(execution)
            .is_some_and(|record| record.readiness.is_unavailable())
    }

    /// The supervisor enforces every sandbox lease at the clock's reading.
    fn enforce(&mut self) -> Result<TickReport, HostError> {
        let report = {
            let mut port = port!(self.parts);
            self.supervisor.tick(&mut port)
        };
        self.settle();
        Ok(report?)
    }

    /// What follows every supervisor call: the channels of each boot that lost authority
    /// close, "channels closed" is acknowledged for each sandbox under revocation with no
    /// channel left open and its revocation advanced, and the sink is given what the
    /// supervisor and the port recorded.
    fn settle(&mut self) {
        self.close_lapsed();
        for execution in self.acknowledge_closed() {
            self.advance_revocation(&execution);
        }
        self.record_audit();
    }

    /// Advances `execution`'s revocation once through the port; the outcome goes to the
    /// log.
    fn advance_revocation(&mut self, execution: &ExecutionId) {
        let outcome = {
            let mut port = port!(self.parts);
            self.supervisor.advance(execution, &mut port)
        };
        self.log.advances.push(RevocationAdvanced {
            execution: execution.clone(),
            at: self.parts.clock.now(),
            outcome,
        });
    }

    /// Closes the channels of each boot that no longer holds authority: its sandbox is not
    /// in a state that holds it, or holds it for another boot or VM.
    fn close_lapsed(&mut self) {
        let now = self.parts.clock.now();
        for session in self.sessions.values_mut() {
            if !session.is_open() {
                continue;
            }
            let current = self.supervisor.coordinator().sandbox(session.execution());
            let this_boot = current.is_some_and(|sandbox| {
                sandbox.generations().boot == session.boot() && sandbox.vm() == Some(session.vm())
            });
            let state = current.map(|sandbox| sandbox.state());
            if this_boot && state.is_some_and(SandboxState::holds_authority) {
                continue;
            }
            let cause = if this_boot && self.supervisor.revocation(session.execution()).is_some() {
                ClosureCause::Revoked
            } else {
                ClosureCause::AuthorityLost { state }
            };
            let closure = session.close(cause, now);
            self.log.closures.push(closure);
        }
    }

    /// Acknowledges "channels closed" as a host observation for every sandbox under
    /// revocation that has not had it and has no channel open in this host: every guest
    /// channel of a boot rides its link (§3.2 line 2070), and the host closed and dropped
    /// it. A boot whose link a transport carries is acknowledged only once that stream
    /// ended ([`TransportState::Ended`]): the closure in the host's session state alone
    /// does not stand for the stream's closure. Returns the sandboxes whose acknowledgment
    /// was recorded.
    fn acknowledge_closed(&mut self) -> Vec<ExecutionId> {
        let now = self.parts.clock.now();
        let pending: Vec<(ExecutionId, Option<TransportEnd>)> = self
            .supervisor
            .sandboxes()
            .map(|record| record.identity.execution.clone())
            // A sandbox a connection gate still serves a caller of has a channel open
            // outside the link (M14): not closed in fact yet.
            .filter(|execution| !self.held_channels.contains(execution))
            .filter(|execution| {
                self.supervisor.revocation(execution).is_some_and(|run| {
                    run.acknowledged_at(Acknowledgment::ChannelsClosed)
                        .is_none()
                })
            })
            .filter_map(|execution| match self.sessions.get(&execution) {
                None => Some((execution, None)),
                Some(session) if session.is_open() => None,
                Some(session) => match session.transport() {
                    TransportState::NotAttached => Some((execution, None)),
                    TransportState::Attached => None,
                    TransportState::Ended(end) => Some((execution, Some(end))),
                },
            })
            .collect();
        let mut recorded = Vec::new();
        for (execution, transport_end) in pending {
            let outcome = self
                .supervisor
                .acknowledge(&execution, Acknowledgment::ChannelsClosed);
            if outcome.is_ok() {
                recorded.push(execution.clone());
            }
            self.log.acknowledgments.push(ChannelsAcknowledged {
                execution,
                at: now,
                transport_end,
                outcome,
            });
        }
        recorded
    }

    /// Gives the sink every lifecycle receipt, every refused launch and every launch record
    /// it was not given yet, in that order; each outcome goes to the log.
    fn record_audit(&mut self) {
        let drain = &mut self.log.audit;
        for receipt in self.supervisor.take_receipts() {
            let outcome = self.parts.sink.record_receipt(&receipt);
            drain.receipts.push((receipt, outcome));
        }
        for refused in self.parts.table.take_refused() {
            let outcome = self.parts.sink.record_refusal(&refused);
            drain.refusals.push((refused, outcome));
        }
        let audited = &self.parts.audited;
        let new: Vec<_> = self
            .parts
            .table
            .records()
            .filter(|record| !audited.contains(&record.identity()))
            .cloned()
            .collect();
        for record in new {
            let outcome = self.parts.sink.record_launch(&record);
            self.parts.audited.insert(record.identity());
            drain.launches.push((record.identity(), outcome));
        }
    }
}
