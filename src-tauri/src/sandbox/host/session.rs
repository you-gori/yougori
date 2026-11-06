//! One sandbox boot's objects (module docs in `mod.rs`): the handle of the VM the host
//! launched, the guest link bound to that VM instance, boot generation and connection,
//! the guest-file adapter of the link's file channel and the commands on its terminal
//! channel (VM part §3.2 lines 2059–2077; §6.1 line 2294: "bind each channel and
//! capability to the correct tuple").
//!
//! Nothing here comes from the guest: the link's binding, the channel's identity and its
//! operation are made from the VM object the coordinator recorded and the handle the
//! supervisor keeps (§3.2 line 2073).

use std::collections::{BTreeSet, VecDeque};
use std::fmt;
use std::time::Duration;

use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{
    Clock, DigestBuilder, ExecutionId, IdError, MonotonicTime, OperationId, SandboxBootGeneration,
    TenantId, TrustScope,
};
use crate::sandbox::guest_files::{BodyTransfers, ChannelIdentity, FilesLimits, GuestFiles};
use crate::sandbox::lifecycle::VmHandle;
use crate::sandbox::link::{
    BootstrapSecret, Channel, CloseReason, Connection, ConnectionNonce, GrantHandle, GuestRequest,
    HostLink, HostMessage, LinkBinding, LinkEvent, LinkLimits, LinkName, LinkPhase, OpenRefusalCause,
    SendRefusal, Shutdown, StreamId,
};
use crate::sandbox::link_transport::TransportEnd;
use crate::sandbox_contract::file_protocol::FileDispatcher;

use super::error::HostError;
use super::log::{ChannelClosure, ClosureCause, Delivery, RefusedOpen};
use super::egress::{EgressEndCause, EgressEvent, EgressStreams};
use super::ingress::{IngressEndCause, IngressEvent, IngressStreams};
use super::terminal::{CommandEnd, CommandRequest, CommandResult, TerminalCommands};

/// Domain of [`channel_operation`].
pub const CHANNEL_DOMAIN: &str = "yougori/sandbox/host/channel/v1";

/// The operation identity of one boot's file channel: `op-` and the hex digest of the
/// execution, the VM instance and the boot generation under [`CHANNEL_DOMAIN`]. It is
/// unique among the channels the host opens, and each body's CORE-05 operation is derived
/// from it (`sandbox::guest_files::body_operation`).
pub fn channel_operation(
    execution: &ExecutionId,
    vm: VmInstanceId,
    boot: SandboxBootGeneration,
) -> Result<OperationId, IdError> {
    let digest = DigestBuilder::new(CHANNEL_DOMAIN)
        .str(execution.as_str())
        .digest(&vm.digest())
        .u64(boot.get())
        .finish();
    OperationId::new(format!("op-{}", digest.to_hex()))
}

/// What the caller gives for one boot's channels; the identity comes from the host.
pub struct ChannelSetup<C: Clock> {
    /// The per-instance bootstrap secret delivered to the guest at launch (§3.2 line
    /// 2075). It is consumed into the link's binding.
    pub secret: BootstrapSecret,
    /// The nonce for this connection of the boot's link (M06-LC), drawn with
    /// [`ConnectionNonce::draw`]: the link's challenge sends it and every frame must carry
    /// it. The host refuses a nonce already used in the boot.
    pub connection: ConnectionNonce,
    /// The trust scope the host gives this VM; every grant must be made for it.
    pub scope: TrustScope,
    /// The link's limits. Each bulk channel's receive window must be the protocol's
    /// default (`LinkLimits::default()`): the welcome carries no windows, so the guest
    /// sends as far as the default window, and a smaller host window would close the
    /// channel under a well-behaved guest. Other windows are refused
    /// ([`HostError::NonProtocolWindow`]).
    pub link_limits: LinkLimits,
    pub files_limits: FilesLimits,
    /// The host's transfer key and ports and the issuer of body grants.
    pub transfers: BodyTransfers,
    /// The grants the file channel starts with, each with its dispatcher.
    pub grants: Vec<(GrantHandle, FileDispatcher<C>)>,
}

impl<C: Clock> fmt::Debug for ChannelSetup<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelSetup")
            .field("secret", &self.secret)
            .field("connection", &self.connection)
            .field("scope", &self.scope)
            .field("link_limits", &self.link_limits)
            .field("files_limits", &self.files_limits)
            .field(
                "grants",
                &self
                    .grants
                    .iter()
                    .map(|(grant, _)| *grant)
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// Whether a transport carries the boot's link, as the host knows it from the stream's
/// owner: the session pump attaches when it is made over the boot's stream and reports the
/// stream's end once it shut the stream down; an owner that drops a stream without a pump
/// reports the same. The host acknowledges "channels closed" for a carried boot only once
/// its stream ended, so a physical channel is never acknowledged closed from the host's
/// session state alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportState {
    /// No transport ever carried this boot's link: its channels never left the host's
    /// memory, and closing the session closes everything there is.
    NotAttached,
    /// A transport carries the link now.
    Attached,
    /// The transport that carried the link ended as stated.
    Ended(TransportEnd),
}

/// The objects of one sandbox boot. Its channels are open from
/// [`super::SandboxHost::open_channels`] until the host closes them, and never again after.
pub struct BootSession<C: Clock> {
    execution: ExecutionId,
    handle: VmHandle,
    link_limits: LinkLimits,
    /// `None` once the host closed the boot's channels.
    link: Option<HostLink<C>>,
    files: GuestFiles<C>,
    commands: TerminalCommands,
    egress: EgressStreams,
    ingress: IngressStreams,
    /// The frames the link left when the host closed it (its close frame), for the
    /// session pump to write before it shuts the stream.
    closing: VecDeque<Vec<u8>>,
    /// Every connection nonce a link of this boot was bound to; none is used twice.
    connections: BTreeSet<Connection>,
    /// The reason the host closed the channels with, once it did.
    closed_reason: Option<CloseReason>,
    transport: TransportState,
    opened_at: MonotonicTime,
    closed_at: Option<MonotonicTime>,
}

impl<C: Clock> fmt::Debug for BootSession<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BootSession")
            .field("execution", &self.execution)
            .field("handle", &self.handle)
            .field("link", &self.link)
            .field("files", &self.files)
            .field("commands", &self.commands)
            .field("transport", &self.transport)
            .field("opened_at", &self.opened_at)
            .field("closed_at", &self.closed_at)
            .finish()
    }
}

impl<C: Clock> BootSession<C> {
    /// The channels of the boot behind `handle`: the file channel's identity from the
    /// handle, `tenant` and the execution; the link bound to the handle's VM instance and
    /// boot generation with `setup.secret` and to `setup.connection`, its challenge queued
    /// as its first frame. Limits whose bulk windows are not the protocol's are refused.
    /// Every grant is attached, or nothing opens.
    pub(super) fn open(
        execution: ExecutionId,
        handle: VmHandle,
        tenant: TenantId,
        clock: C,
        setup: ChannelSetup<C>,
    ) -> Result<Self, HostError> {
        let ChannelSetup {
            secret,
            connection,
            scope,
            link_limits,
            files_limits,
            transfers,
            grants,
        } = setup;
        protocol_windows(&link_limits)?;
        let operation =
            channel_operation(&execution, handle.vm, handle.boot).map_err(HostError::Identifier)?;
        let identity = ChannelIdentity {
            vm: handle.vm,
            boot: handle.boot,
            scope,
            tenant,
            parent: execution.clone(),
            operation,
        };
        let mut files = GuestFiles::new(identity, link_limits, transfers, files_limits)
            .map_err(HostError::Files)?;
        for (grant, dispatcher) in grants {
            files
                .add_grant(grant, dispatcher)
                .map_err(|refused| HostError::Grant {
                    grant,
                    error: refused.error,
                })?;
        }
        let opened_at = clock.now();
        let link = HostLink::connect(
            LinkBinding::new(handle.vm, handle.boot, secret),
            connection,
            link_limits,
            clock,
        )
        .map_err(HostError::Link)?;
        Ok(Self {
            execution,
            handle,
            link_limits,
            link: Some(link),
            files,
            commands: TerminalCommands::new(),
            egress: EgressStreams::new(),
            ingress: IngressStreams::new(),
            closing: VecDeque::new(),
            connections: BTreeSet::from([connection.connection()]),
            closed_reason: None,
            transport: TransportState::NotAttached,
            opened_at,
            closed_at: None,
        })
    }

    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    /// The handle of the VM the host launched for this boot.
    pub fn handle(&self) -> &VmHandle {
        &self.handle
    }

    pub fn vm(&self) -> VmInstanceId {
        self.handle.vm
    }

    pub fn boot(&self) -> SandboxBootGeneration {
        self.handle.boot
    }

    /// The boot's link, until the host closed its channels.
    pub fn link(&self) -> Option<&HostLink<C>> {
        self.link.as_ref()
    }

    pub fn files(&self) -> &GuestFiles<C> {
        &self.files
    }

    /// Whether the host has not closed the boot's channels. The link itself may have
    /// closed (the guest closed it, a violation, a timeout); a closed link can be replaced
    /// ([`super::SandboxHost::reconnect`]).
    pub fn is_open(&self) -> bool {
        self.link.is_some()
    }

    /// Whether the link completed its handshake and is open.
    pub fn link_is_open(&self) -> bool {
        self.link
            .as_ref()
            .is_some_and(|link| matches!(link.phase(), LinkPhase::Open))
    }

    /// Whether guest bytes are still taken: the host has not closed the boot's channels
    /// and the link has not closed.
    pub fn takes_bytes(&self) -> bool {
        self.link.as_ref().is_some_and(|link| !link.is_closed())
    }

    /// Frames waiting for the transport: the link's, or after the host closed the
    /// channels, what the link left (its close frame).
    pub fn queued_outbound(&self) -> usize {
        match &self.link {
            Some(link) => link.queued_frames(),
            None => self.closing.len(),
        }
    }

    /// Commands running on the terminal channel.
    pub fn running_commands(&self) -> usize {
        self.commands.running()
    }

    /// Whether a link of this boot was bound to `connection` already.
    pub fn used_connection(&self, connection: Connection) -> bool {
        self.connections.contains(&connection)
    }

    /// Whether a transport carries the boot's link, and how it ended if it did.
    pub fn transport(&self) -> TransportState {
        self.transport
    }

    /// Why the link side closed, once it did: the link's own close cause, or the reason
    /// the host closed the channels with. `None` while the link is open.
    pub fn close_reason(&self) -> Option<CloseReason> {
        match &self.link {
            Some(link) => match link.phase() {
                LinkPhase::Closed(cause) => Some(cause.close_reason()),
                _ => None,
            },
            None => self.closed_reason,
        }
    }

    /// A transport takes the boot's link: refused while another carries it.
    pub(super) fn attach_transport(&mut self) -> Result<(), HostError> {
        if self.transport == TransportState::Attached {
            return Err(HostError::TransportAttached {
                execution: self.execution.clone(),
                boot: self.handle.boot,
            });
        }
        self.transport = TransportState::Attached;
        Ok(())
    }

    /// The transport that carried the link ended: `end` is how.
    pub(super) fn transport_ended(&mut self, end: TransportEnd) -> Result<(), HostError> {
        if self.transport != TransportState::Attached {
            return Err(HostError::NoTransport {
                execution: self.execution.clone(),
                boot: self.handle.boot,
            });
        }
        self.transport = TransportState::Ended(end);
        Ok(())
    }

    /// Asks the guest to shut down within `grace` (the link's `Shutdown` message, urgent):
    /// the link must have completed its handshake. The guest powers off when it complies;
    /// the host observes that as the stream ending and the VM's process ending, never from
    /// the request.
    pub(super) fn request_shutdown(&mut self, grace: Duration) -> Result<(), HostError> {
        let execution = self.execution.clone();
        let boot = self.handle.boot;
        let Some(link) = self.link.as_mut() else {
            return Err(HostError::ChannelsClosed { execution, boot });
        };
        if !matches!(link.phase(), LinkPhase::Open) {
            return Err(HostError::LinkNotOpen { execution });
        }
        let grace_seconds = u32::try_from(grace.as_secs()).unwrap_or(u32::MAX);
        link.send(HostMessage::Shutdown(Shutdown { grace_seconds }))
            .map_err(HostError::Unsent)
    }

    pub fn opened_at(&self) -> MonotonicTime {
        self.opened_at
    }

    pub fn closed_at(&self) -> Option<MonotonicTime> {
        self.closed_at
    }

    pub(super) fn link_limits(&self) -> LinkLimits {
        self.link_limits
    }

    pub(super) fn files_mut(&mut self) -> &mut GuestFiles<C> {
        &mut self.files
    }

    /// The open link and the adapter, for one call; refused once the host closed them.
    pub(super) fn parts_mut(
        &mut self,
    ) -> Result<(&mut HostLink<C>, &mut GuestFiles<C>), HostError> {
        match self.link.as_mut() {
            Some(link) => Ok((link, &mut self.files)),
            None => Err(HostError::ChannelsClosed {
                execution: self.execution.clone(),
                boot: self.handle.boot,
            }),
        }
    }

    /// Replaces a closed link with `link`, bound to the same VM instance and boot and to
    /// a connection no link of the boot used. A command still running on the old link
    /// ends as the old link closed, reported in the next delivery.
    pub(super) fn replace_link(
        &mut self,
        link: HostLink<C>,
        now: MonotonicTime,
    ) -> Result<(), HostError> {
        match self.link.as_ref() {
            None => Err(HostError::ChannelsClosed {
                execution: self.execution.clone(),
                boot: self.handle.boot,
            }),
            Some(current) if !current.is_closed() => Err(HostError::LinkOpen {
                execution: self.execution.clone(),
                boot: self.handle.boot,
            }),
            Some(_) if self.connections.contains(&link.connection()) => {
                Err(HostError::ConnectionReused {
                    execution: self.execution.clone(),
                    boot: self.handle.boot,
                })
            }
            Some(current) => {
                if let LinkPhase::Closed(cause) = current.phase() {
                    let end = CommandEnd::LinkClosed {
                        cause: cause.clone(),
                    };
                    self.commands.end_all_later(end, now);
                    self.egress.end_all_later(EgressEndCause::LinkClosed {
                        close: cause.clone(),
                    });
                    self.ingress.end_all_later(IngressEndCause::LinkClosed {
                        close: cause.clone(),
                    });
                }
                self.connections.insert(link.connection());
                self.link = Some(link);
                Ok(())
            }
        }
    }

    /// The next frame for the transport: the link's, or after the host closed the
    /// channels, what the link left.
    pub(super) fn next_outbound(&mut self) -> Option<Vec<u8>> {
        match self.link.as_mut() {
            Some(link) => link.next_outbound(),
            None => self.closing.pop_front(),
        }
    }

    /// Starts a command on the terminal channel; the link must have completed its
    /// handshake.
    pub(super) fn start_command(
        &mut self,
        request: CommandRequest,
        now: MonotonicTime,
    ) -> Result<StreamId, HostError> {
        let execution = self.execution.clone();
        let boot = self.handle.boot;
        let Some(link) = self.link.as_mut() else {
            return Err(HostError::ChannelsClosed { execution, boot });
        };
        if !matches!(link.phase(), LinkPhase::Open) {
            return Err(HostError::LinkNotOpen { execution });
        }
        self.commands
            .start(link, request, now)
            .map_err(HostError::Command)
    }

    /// Cancels the command on `stream`; it ends with the output so far.
    pub(super) fn cancel_command(
        &mut self,
        stream: StreamId,
        now: MonotonicTime,
    ) -> Result<CommandResult, HostError> {
        let Some(link) = self.link.as_mut() else {
            return Err(HostError::ChannelsClosed {
                execution: self.execution.clone(),
                boot: self.handle.boot,
            });
        };
        self.commands
            .cancel(link, stream, now)
            .map_err(HostError::Command)
    }

    /// Routes the link's `events` at `now`: commands past their time limit end first; the
    /// terminal channel's events go to the commands, the file channel's to the adapter,
    /// which answers on the same link, and guest reports and everything else to the
    /// caller. While `refuse_opens`, a guest's new file stream is refused here, before the
    /// adapter, with `Unavailable`. Afterwards the commands send what the link takes now.
    pub(super) fn route(
        &mut self,
        events: Vec<LinkEvent>,
        refuse_opens: bool,
        now: MonotonicTime,
    ) -> Result<Delivery, HostError> {
        let Self {
            link,
            files,
            commands,
            egress,
            ingress,
            execution,
            handle,
            ..
        } = self;
        let Some(link) = link.as_mut() else {
            return Err(HostError::ChannelsClosed {
                execution: execution.clone(),
                boot: handle.boot,
            });
        };
        let mut delivery = Delivery::default();
        commands.expire(link, now);
        for event in events {
            let Some(event) = commands.handle(link, event, now) else {
                continue;
            };
            let Some(event) = egress.handle(link, event, now) else {
                continue;
            };
            let Some(event) = ingress.handle(link, event, now) else {
                continue;
            };
            let event = match event {
                LinkEvent::Request(GuestRequest::OpenFile { stream, grant, .. })
                    if refuse_opens =>
                {
                    let unsent = link
                        .send(HostMessage::OpenRefused {
                            channel: Channel::File,
                            stream,
                            cause: OpenRefusalCause::Unavailable,
                        })
                        .err();
                    delivery.refused_opens.push(RefusedOpen {
                        stream,
                        grant,
                        unsent,
                    });
                    continue;
                }
                LinkEvent::Report(report) => {
                    delivery.reports.push(report);
                    continue;
                }
                other => other,
            };
            if let LinkEvent::Closed(cause) = &event {
                delivery.closed = Some(cause.clone());
            }
            if GuestFiles::<C>::is_file_event(&event) {
                let done = files.handle(link, event).map_err(HostError::Mismatch)?;
                delivery.files.extend(done);
            } else {
                delivery.other.push(event);
            }
        }
        commands.pump(link);
        egress.pump(link);
        ingress.pump(link);
        delivery.commands = commands.take_events();
        delivery.egress = egress.take_events();
        delivery.ingress = ingress.take_events();
        Ok(delivery)
    }

    /// Closes the boot's channels for `cause` at `now`: every grant comes off the file
    /// channel (its streams cancelled as revoked, its bodies ended, its dispatcher dropped),
    /// every running command ends with `cause`, then the link closes with `cause`'s reason
    /// and is dropped; the close frame is kept for the transport (in the closure, and for
    /// the session pump). Only frames queued after the link closed (its close frame) are
    /// taken, so nothing queued before the closure reaches the guest. A link that refuses
    /// the close frame is dropped without one. Closing again does nothing.
    pub(super) fn close(&mut self, cause: ClosureCause, now: MonotonicTime) -> ChannelClosure {
        let grants: Vec<GrantHandle> = self.files.grants().collect();
        let mut files = Vec::new();
        for grant in &grants {
            if let Some(removed) = self.files.remove_grant(*grant) {
                files.extend(removed.events);
            }
        }
        let commands = self.commands.end_all(CommandEnd::HostClosed { cause }, now);
        let egress = self
            .egress
            .end_all(EgressEndCause::HostClosed { closure: cause });
        let ingress = self
            .ingress
            .end_all(IngressEndCause::HostClosed { closure: cause });
        let mut link_closed_before = None;
        let mut close_refused: Option<SendRefusal> = None;
        let mut final_frames = Vec::new();
        if let Some(mut link) = self.link.take() {
            if let LinkPhase::Closed(before) = link.phase() {
                link_closed_before = Some(before.clone());
            } else if let Err(refusal) = link.send(HostMessage::Close {
                reason: cause.close_reason(),
            }) {
                close_refused = Some(refusal);
            }
            if link.is_closed() {
                while let Some(frame) = link.next_outbound() {
                    final_frames.push(frame);
                }
            }
            files.extend(self.files.link_lost());
            self.closing.extend(final_frames.iter().cloned());
            self.closed_reason = Some(cause.close_reason());
            self.closed_at = Some(now);
        }
        ChannelClosure {
            execution: self.execution.clone(),
            boot: self.handle.boot,
            vm: self.handle.vm,
            cause,
            at: now,
            grants,
            files,
            commands,
            egress,
            ingress,
            link_closed_before,
            close_refused,
            final_frames,
        }
    }

    // ----- the egress channel ------------------------------------------------------------

    /// Whether the boot accepts guest egress opens (a port is attached).
    pub(super) fn set_egress_accepting(&mut self, accepting: bool) {
        self.egress.set_accepting(accepting);
    }

    pub fn egress_accepting(&self) -> bool {
        self.egress.is_accepting()
    }

    pub fn egress_streams(&self) -> usize {
        self.egress.open_streams()
    }

    pub fn egress_send_room(&self, stream: StreamId) -> usize {
        self.egress.send_room(stream)
    }

    /// Queues `bytes` for the guest on egress `stream` and writes what the link takes now;
    /// the events that produced (a stream finished) are returned.
    pub(super) fn write_egress(
        &mut self,
        stream: StreamId,
        bytes: &[u8],
    ) -> Result<Vec<EgressEvent>, HostError> {
        let execution = self.execution.clone();
        let boot = self.handle.boot;
        let Some(link) = self.link.as_mut() else {
            return Err(HostError::ChannelsClosed { execution, boot });
        };
        self.egress
            .write(stream, bytes)
            .map_err(|refusal| HostError::Egress { execution, refusal })?;
        self.egress.pump(link);
        Ok(self.egress.take_events())
    }

    /// Ends the host's direction of egress `stream` once its pending bytes went out.
    pub(super) fn end_egress(&mut self, stream: StreamId) -> Result<Vec<EgressEvent>, HostError> {
        let execution = self.execution.clone();
        let boot = self.handle.boot;
        let Some(link) = self.link.as_mut() else {
            return Err(HostError::ChannelsClosed { execution, boot });
        };
        self.egress
            .end(stream)
            .map_err(|refusal| HostError::Egress { execution, refusal })?;
        self.egress.pump(link);
        Ok(self.egress.take_events())
    }

    /// Detaches the port: no more opens are accepted and every open stream of the port is
    /// cancelled (a sandbox connection's stays).
    pub(super) fn detach_egress(&mut self) -> Result<Vec<EgressEvent>, HostError> {
        self.egress.set_accepting(false);
        let execution = self.execution.clone();
        let boot = self.handle.boot;
        let Some(link) = self.link.as_mut() else {
            return Err(HostError::ChannelsClosed { execution, boot });
        };
        self.egress.cancel_relayed(link);
        Ok(self.egress.take_events())
    }

    /// The boot's sandbox connection endpoints (M14): opens naming one are accepted with or
    /// without a port, and their bytes credited as the connection consumes them.
    pub(super) fn set_egress_connections(&mut self, names: std::collections::BTreeSet<LinkName>) {
        self.egress.set_connections(names);
    }

    /// `bytes` of egress `stream`'s data were consumed; their credit goes back to the guest,
    /// written with what the link takes now.
    pub(super) fn consume_egress(&mut self, stream: StreamId, bytes: u64) -> Vec<EgressEvent> {
        self.egress.consumed(stream, bytes);
        if let Some(link) = self.link.as_mut() {
            self.egress.pump(link);
        }
        self.egress.take_events()
    }

    /// Cancels egress `stream` on the link: the port's side failed.
    pub(super) fn cancel_egress(&mut self, stream: StreamId) -> Result<Vec<EgressEvent>, HostError> {
        let execution = self.execution.clone();
        let boot = self.handle.boot;
        let Some(link) = self.link.as_mut() else {
            return Err(HostError::ChannelsClosed { execution, boot });
        };
        self.egress
            .cancel(link, stream)
            .map_err(|refusal| HostError::Egress { execution, refusal })?;
        Ok(self.egress.take_events())
    }

    // ----- the ingress channel -----------------------------------------------------------

    pub fn ingress_streams(&self) -> usize {
        self.ingress.open_streams()
    }

    /// Opens an ingress stream to the guest's `listener`; the link must have completed its
    /// handshake. The guest's answer comes in a later delivery.
    pub(super) fn open_ingress(&mut self, listener: LinkName) -> Result<StreamId, HostError> {
        let execution = self.execution.clone();
        let boot = self.handle.boot;
        let Some(link) = self.link.as_mut() else {
            return Err(HostError::ChannelsClosed { execution, boot });
        };
        if !matches!(link.phase(), LinkPhase::Open) {
            return Err(HostError::LinkNotOpen { execution });
        }
        self.ingress
            .open(link, listener)
            .map_err(|refusal| HostError::Ingress { execution, refusal })
    }

    /// Queues `bytes` for the guest on ingress `stream` and writes what the link takes now;
    /// the events that produced (a stream finished) are returned.
    pub(super) fn write_ingress(
        &mut self,
        stream: StreamId,
        bytes: &[u8],
    ) -> Result<Vec<IngressEvent>, HostError> {
        let execution = self.execution.clone();
        let boot = self.handle.boot;
        let Some(link) = self.link.as_mut() else {
            return Err(HostError::ChannelsClosed { execution, boot });
        };
        self.ingress
            .write(stream, bytes)
            .map_err(|refusal| HostError::Ingress { execution, refusal })?;
        self.ingress.pump(link);
        Ok(self.ingress.take_events())
    }

    /// Ends the host's direction of ingress `stream` once its pending bytes went out.
    pub(super) fn end_ingress(&mut self, stream: StreamId) -> Result<Vec<IngressEvent>, HostError> {
        let execution = self.execution.clone();
        let boot = self.handle.boot;
        let Some(link) = self.link.as_mut() else {
            return Err(HostError::ChannelsClosed { execution, boot });
        };
        self.ingress
            .end(stream)
            .map_err(|refusal| HostError::Ingress { execution, refusal })?;
        self.ingress.pump(link);
        Ok(self.ingress.take_events())
    }

    /// `bytes` of the guest's data on ingress `stream` were taken by its caller (or never
    /// will be); their credit goes back to the stream, written with what the link takes now.
    pub(super) fn consume_ingress(&mut self, stream: StreamId, bytes: u64) -> Vec<IngressEvent> {
        self.ingress.consumed(stream, bytes);
        if let Some(link) = self.link.as_mut() {
            self.ingress.pump(link);
        }
        self.ingress.take_events()
    }

    /// Cancels ingress `stream` on the link: its caller went away or was closed.
    pub(super) fn cancel_ingress(
        &mut self,
        stream: StreamId,
    ) -> Result<Vec<IngressEvent>, HostError> {
        let execution = self.execution.clone();
        let boot = self.handle.boot;
        let Some(link) = self.link.as_mut() else {
            return Err(HostError::ChannelsClosed { execution, boot });
        };
        self.ingress
            .cancel(link, stream)
            .map_err(|refusal| HostError::Ingress { execution, refusal })?;
        Ok(self.ingress.take_events())
    }
}

/// Refuses limits whose bulk receive windows are not the protocol's defaults, which the
/// guest assumes because the welcome does not carry them.
fn protocol_windows(limits: &LinkLimits) -> Result<(), HostError> {
    let protocol = LinkLimits::default();
    for channel in Channel::BULK {
        let window_bytes = limits.quota(channel).max_buffered_bytes;
        let protocol_bytes = protocol.quota(channel).max_buffered_bytes;
        if window_bytes != protocol_bytes {
            return Err(HostError::NonProtocolWindow {
                channel,
                window_bytes,
                protocol_bytes,
            });
        }
    }
    Ok(())
}
