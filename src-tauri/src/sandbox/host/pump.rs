//! The session pump (module docs in `mod.rs`): carries one boot's link over that boot's
//! byte stream, so the link the [`SandboxHost`] owns is the one on the wire (VM part §3.2
//! lines 2059–2077; VM-W06 line 2591; VM-P28 line 2803; §6.3 lines 2309–2316).
//!
//! It lives here rather than in `sandbox::link_transport` because it drives the host's
//! routes ([`SandboxHost::receive`], [`SandboxHost::next_outbound`],
//! [`SandboxHost::peer_closed`]); the transport module stays below the host and only
//! lends it its bounded stream I/O ([`StreamIo`]), the same reads, writes and stall
//! timeout as `LinkDriver`.
//!
//! Each [`SessionPump::step`] writes what the boot's link has queued, one frame at a time
//! and only when the stream takes it now (so a revocation queued later still goes before
//! bulk frames queued earlier), reads at most the configured chunks and hands them to
//! [`SandboxHost::receive`], which enforces the sandbox leases and the boot's authority
//! before routing anything, then writes again. A read of zero bytes or a failed call
//! reaches the host as [`SandboxHost::peer_closed`]. Once the link closed, or the host
//! closed the boot's channels (a revocation, a lost authority, a shutdown), the pump reads
//! nothing more, writes what the stream's close policy allows ([`StreamIo`], review
//! finding R2: after an orderly close the frame already taken and then the close frame,
//! after any other close only the close frame, and a partly written frame abandons the
//! stream at once with [`TransportEnd::Aborted`]) and then shuts the stream down
//! ([`StreamShutdown`]) and finishes. A failed stream is shut down too and nothing more
//! is written.
//!
//! The pump is the owner of the stream the host knows about: making one attaches the
//! transport to the boot ([`SandboxHost::attach_transport`]), and finishing reports the
//! stream's end to the host ([`SandboxHost::transport_ended`]), which is what lets the
//! host acknowledge "channels closed" for a boot under revocation: the physical closure,
//! not the session state. An owner that must drop the stream before the pump finished
//! (a launch that failed after the stream was connected) calls [`SessionPump::abandon`],
//! which shuts the stream down and reports [`TransportEnd::Abandoned`].
//!
//! The stream is a [`CheckedStream`]: the launch's link socket, admitted by
//! `LinkSocketEndpoint` only when its peer is the QEMU process the host started, so the
//! peer check cannot be skipped. One pump per boot connection, from its first frame: a
//! pump is refused for a link that already gave frames to another transport. The link's
//! handshake timeout starts when the pump writes the challenge, so the time QEMU and the
//! connection took before the pump existed does not count against the guest's hello. No thread is spawned here. The caller's
//! loop, for each boot it carries: call [`SessionPump::step`] and act on its events (the
//! deliveries' commands, reports, file events and closes); call [`SandboxHost::tick`]
//! about once a second and [`SessionPump::flush`] after it and after every host call that
//! queues frames (a started or cancelled command, a revocation); stop when
//! [`SessionPump::is_finished`] and drop the stream. The stream's reads must return
//! within a short bound (a read timeout or a non-blocking stream), since one caller
//! drives every pump and the host's ticks.

use std::fmt;
use std::io::{Read, Write};

use crate::foundation::coordination::CapacityPort;
use crate::foundation::events::AuditSpool;
use crate::foundation::ids::{Clock, ExecutionId};
use crate::sandbox::audit::{HeadAnchor, SegmentStorage};
use crate::sandbox::backend::VmBackend as ContractBackend;
use crate::sandbox::integration::ReservationResolver;
use crate::sandbox::link::CloseReason;
use crate::sandbox::link_transport::{
    CheckedStream, DriverCounters, DriverLimits, DriverLimitsError, DriverPhase, FrameEnd,
    StreamIo, StreamShutdown, StreamStop, TransportEnd, TransportEvent, TransportFailure,
    TransportOperation, WriteStop,
};

use super::error::HostError;
use super::log::Delivery;
use super::sandbox_host::SandboxHost;
use super::session::BootSession;

/// What one pump call produced, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PumpEvent {
    /// What the host made of bytes read from the stream, or of its end.
    Delivered(Delivery),
    /// The host did not take bytes read from the stream (its channels for the boot
    /// closed in the same call, or it holds none); they were dropped.
    Refused(HostError),
    Transport(TransportEvent),
    /// The pump shut the stream down after its last frame; the failure, if that failed.
    ShutDown {
        failure: Option<TransportFailure>,
    },
    /// The host did not take the report that the stream ended (the boot's channels are
    /// gone from the host).
    EndNotReported(HostError),
}

/// Why a pump was not made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PumpRefusal {
    Limits(DriverLimitsError),
    /// The host holds no channels of the execution, or has closed them.
    Host(Box<HostError>),
    /// The boot's link already gave frames to another transport.
    ConnectionStarted {
        sent_frames: u64,
    },
}

impl fmt::Display for PumpRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => write!(f, "driver limits: {error}"),
            Self::Host(error) => write!(f, "{error}"),
            Self::ConnectionStarted { sent_frames } => write!(
                f,
                "the link already gave {sent_frames} frames to another transport"
            ),
        }
    }
}

impl std::error::Error for PumpRefusal {}

/// Carries one boot's link over one checked byte stream (module docs).
pub struct SessionPump<T: Read + Write + StreamShutdown> {
    execution: ExecutionId,
    io: StreamIo<CheckedStream<T>>,
    phase: DriverPhase,
}

impl<T: Read + Write + StreamShutdown> SessionPump<T> {
    /// A pump for `execution`'s boot over `transport`, a stream whose peer was checked,
    /// under `limits`, which are validated first: refused unless the host holds the boot's
    /// open channels, no other transport carries its link, and its link has not written a
    /// frame yet, so the pump carries the connection from its challenge. The transport is
    /// attached to the boot in the host.
    pub fn new<C, P, B, R, S, Q, A>(
        host: &mut SandboxHost<C, P, B, R, S, Q, A>,
        execution: ExecutionId,
        transport: CheckedStream<T>,
        limits: DriverLimits,
    ) -> Result<Self, PumpRefusal>
    where
        C: Clock + Clone,
        P: CapacityPort,
        B: ContractBackend,
        R: ReservationResolver,
        S: SegmentStorage,
        Q: AuditSpool,
        A: HeadAnchor,
    {
        let session = host.session(&execution).ok_or_else(|| {
            PumpRefusal::Host(Box::new(HostError::NoChannels {
                execution: execution.clone(),
            }))
        })?;
        let Some(link) = session.link() else {
            return Err(PumpRefusal::Host(Box::new(HostError::ChannelsClosed {
                execution: execution.clone(),
                boot: session.boot(),
            })));
        };
        let sent_frames = link.last_sent_sequence();
        if sent_frames != 0 {
            return Err(PumpRefusal::ConnectionStarted { sent_frames });
        }
        let io =
            StreamIo::new(transport, limits, host.clock().now()).map_err(PumpRefusal::Limits)?;
        host.attach_transport(&execution)
            .map_err(|error| PumpRefusal::Host(Box::new(error)))?;
        Ok(Self {
            execution,
            io,
            phase: DriverPhase::Running,
        })
    }

    /// Ends the stream before the link finished with it: nothing more is written or read,
    /// the stream is shut down, and the host learns the transport ended
    /// ([`TransportEnd::Abandoned`]). For an owner that must drop the stream (a launch that
    /// failed after it was connected). Nothing happens to a pump that finished.
    pub fn abandon<C, P, B, R, S, Q, A>(
        &mut self,
        host: &mut SandboxHost<C, P, B, R, S, Q, A>,
    ) -> Vec<PumpEvent>
    where
        C: Clock + Clone,
        P: CapacityPort,
        B: ContractBackend,
        R: ReservationResolver,
        S: SegmentStorage,
        Q: AuditSpool,
        A: HeadAnchor,
    {
        let mut events = Vec::new();
        if self.is_finished() {
            return events;
        }
        self.io.drop_pending();
        self.finish(host, TransportEnd::Abandoned, &mut events);
        events
    }

    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn phase(&self) -> DriverPhase {
        self.phase
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.phase, DriverPhase::Finished { .. })
    }

    pub fn counters(&self) -> DriverCounters {
        self.io.counters()
    }

    /// Bytes of the frame the stream has not taken yet; never more than one frame.
    pub fn pending_output_bytes(&self) -> usize {
        self.io.pending_output_bytes()
    }

    pub fn transport(&self) -> &CheckedStream<T> {
        self.io.transport()
    }

    pub fn into_transport(self) -> CheckedStream<T> {
        self.io.into_transport()
    }

    /// Writes what the link holds, reads and hands the host at most the configured
    /// chunks, and writes again. Nothing is read once the link or the boot's channels
    /// closed.
    pub fn step<C, P, B, R, S, Q, A>(
        &mut self,
        host: &mut SandboxHost<C, P, B, R, S, Q, A>,
    ) -> Vec<PumpEvent>
    where
        C: Clock + Clone,
        P: CapacityPort,
        B: ContractBackend,
        R: ReservationResolver,
        S: SegmentStorage,
        Q: AuditSpool,
        A: HeadAnchor,
    {
        let mut events = Vec::new();
        if self.is_finished() {
            return events;
        }
        self.write_out(host, &mut events);
        self.settle(host, &mut events);
        if matches!(self.phase, DriverPhase::Running) {
            self.read_in(host, &mut events);
        }
        self.write_out(host, &mut events);
        self.settle(host, &mut events);
        events
    }

    /// Writes what the link holds, without reading (after a tick or a host call that
    /// queued frames).
    pub fn flush<C, P, B, R, S, Q, A>(
        &mut self,
        host: &mut SandboxHost<C, P, B, R, S, Q, A>,
    ) -> Vec<PumpEvent>
    where
        C: Clock + Clone,
        P: CapacityPort,
        B: ContractBackend,
        R: ReservationResolver,
        S: SegmentStorage,
        Q: AuditSpool,
        A: HeadAnchor,
    {
        let mut events = Vec::new();
        self.write_out(host, &mut events);
        self.settle(host, &mut events);
        events
    }

    fn read_in<C, P, B, R, S, Q, A>(
        &mut self,
        host: &mut SandboxHost<C, P, B, R, S, Q, A>,
        events: &mut Vec<PumpEvent>,
    ) where
        C: Clock + Clone,
        P: CapacityPort,
        B: ContractBackend,
        R: ReservationResolver,
        S: SegmentStorage,
        Q: AuditSpool,
        A: HeadAnchor,
    {
        let stop = {
            let mut end = HostEnd {
                host: &mut *host,
                execution: &self.execution,
                events: &mut *events,
            };
            self.io.read(&mut end)
        };
        match stop {
            None => {}
            Some(StreamStop::PeerEnded) => {
                events.push(PumpEvent::Transport(TransportEvent::PeerEnded));
                self.peer_gone(host, events);
            }
            Some(StreamStop::Failed(failure)) => self.fail(host, failure, events),
        }
    }

    fn write_out<C, P, B, R, S, Q, A>(
        &mut self,
        host: &mut SandboxHost<C, P, B, R, S, Q, A>,
        events: &mut Vec<PumpEvent>,
    ) where
        C: Clock + Clone,
        P: CapacityPort,
        B: ContractBackend,
        R: ReservationResolver,
        S: SegmentStorage,
        Q: AuditSpool,
        A: HeadAnchor,
    {
        if self.is_finished() {
            return;
        }
        let now = host.clock().now();
        let stop = {
            let mut end = HostEnd {
                host: &mut *host,
                execution: &self.execution,
                events: &mut *events,
            };
            self.io.write(&mut end, now)
        };
        match stop {
            None => {}
            Some(WriteStop::Failed(failure)) => self.fail(host, failure, events),
            Some(WriteStop::Aborted {
                reason,
                written,
                of,
            }) => {
                // The link side closed already (the host closed the channels, or the link
                // closed itself); the stream is abandoned without a close frame.
                self.finish(
                    host,
                    TransportEnd::Aborted {
                        reason,
                        written,
                        of,
                    },
                    events,
                );
            }
        }
    }

    /// The stream failed: the host learns the guest is gone, nothing more is written, and
    /// the stream is shut down.
    fn fail<C, P, B, R, S, Q, A>(
        &mut self,
        host: &mut SandboxHost<C, P, B, R, S, Q, A>,
        failure: TransportFailure,
        events: &mut Vec<PumpEvent>,
    ) where
        C: Clock + Clone,
        P: CapacityPort,
        B: ContractBackend,
        R: ReservationResolver,
        S: SegmentStorage,
        Q: AuditSpool,
        A: HeadAnchor,
    {
        events.push(PumpEvent::Transport(TransportEvent::Failed { failure }));
        self.io.drop_pending();
        self.peer_gone(host, events);
        let end = if self.io.input_ended() {
            TransportEnd::PeerEnded
        } else {
            TransportEnd::Failed { failure }
        };
        self.finish(host, end, events);
    }

    /// Tells the host the guest is gone, unless its link no longer takes bytes.
    fn peer_gone<C, P, B, R, S, Q, A>(
        &mut self,
        host: &mut SandboxHost<C, P, B, R, S, Q, A>,
        events: &mut Vec<PumpEvent>,
    ) where
        C: Clock + Clone,
        P: CapacityPort,
        B: ContractBackend,
        R: ReservationResolver,
        S: SegmentStorage,
        Q: AuditSpool,
        A: HeadAnchor,
    {
        if !host
            .session(&self.execution)
            .is_some_and(BootSession::takes_bytes)
        {
            return;
        }
        events.push(match host.peer_closed(&self.execution) {
            Ok(delivery) => PumpEvent::Delivered(delivery),
            Err(error) => PumpEvent::Refused(error),
        });
    }

    /// Once the link or the boot's channels closed, the pump drains: it finishes when the
    /// stream took every frame left.
    fn settle<C, P, B, R, S, Q, A>(
        &mut self,
        host: &mut SandboxHost<C, P, B, R, S, Q, A>,
        events: &mut Vec<PumpEvent>,
    ) where
        C: Clock + Clone,
        P: CapacityPort,
        B: ContractBackend,
        R: ReservationResolver,
        S: SegmentStorage,
        Q: AuditSpool,
        A: HeadAnchor,
    {
        if self.is_finished() {
            return;
        }
        let session = host.session(&self.execution);
        if session.is_some_and(BootSession::takes_bytes) {
            return;
        }
        self.phase = DriverPhase::Draining;
        let queued = session.map_or(0, BootSession::queued_outbound);
        if !self.io.has_pending() && queued == 0 {
            let end = if self.io.input_ended() {
                TransportEnd::PeerEnded
            } else {
                TransportEnd::LinkClosed
            };
            self.finish(host, end, events);
        }
    }

    /// Shuts the stream down, finishes, and reports the stream's end to the host, which
    /// may acknowledge the boot's channels closed on it.
    fn finish<C, P, B, R, S, Q, A>(
        &mut self,
        host: &mut SandboxHost<C, P, B, R, S, Q, A>,
        end: TransportEnd,
        events: &mut Vec<PumpEvent>,
    ) where
        C: Clock + Clone,
        P: CapacityPort,
        B: ContractBackend,
        R: ReservationResolver,
        S: SegmentStorage,
        Q: AuditSpool,
        A: HeadAnchor,
    {
        let failure = self
            .io
            .transport_mut()
            .shut_down()
            .err()
            .map(|error| TransportFailure::io(TransportOperation::Shutdown, &error));
        events.push(PumpEvent::ShutDown { failure });
        self.phase = DriverPhase::Finished { end };
        events.push(PumpEvent::Transport(TransportEvent::Finished { end }));
        if let Err(error) = host.transport_ended(&self.execution, end) {
            events.push(PumpEvent::EndNotReported(error));
        }
    }
}

impl<T: Read + Write + StreamShutdown> fmt::Debug for SessionPump<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionPump")
            .field("execution", &self.execution)
            .field("phase", &self.phase)
            .field("io", &self.io)
            .finish()
    }
}

/// The host's side of one boot for one pass of the stream.
struct HostEnd<'a, C, P, B, R, S, Q, A>
where
    C: Clock + Clone,
    P: CapacityPort,
{
    host: &'a mut SandboxHost<C, P, B, R, S, Q, A>,
    execution: &'a ExecutionId,
    events: &'a mut Vec<PumpEvent>,
}

impl<C, P, B, R, S, Q, A> FrameEnd for HostEnd<'_, C, P, B, R, S, Q, A>
where
    C: Clock + Clone,
    P: CapacityPort,
    B: ContractBackend,
    R: ReservationResolver,
    S: SegmentStorage,
    Q: AuditSpool,
    A: HeadAnchor,
{
    fn receive(&mut self, bytes: &[u8]) {
        self.events
            .push(match self.host.receive(self.execution, bytes) {
                Ok(delivery) => PumpEvent::Delivered(delivery),
                Err(error) => PumpEvent::Refused(error),
            });
    }

    fn stops_reading(&self) -> bool {
        !self
            .host
            .session(self.execution)
            .is_some_and(BootSession::takes_bytes)
    }

    fn next_frame(&mut self) -> Option<Vec<u8>> {
        self.host.next_outbound(self.execution).ok().flatten()
    }

    fn close_reason(&self) -> Option<CloseReason> {
        match self.host.session(self.execution) {
            Some(session) => session.close_reason(),
            // The session is gone (torn down): nothing more is written anyway.
            None => Some(CloseReason::Shutdown),
        }
    }
}
