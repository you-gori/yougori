//! The transport driver: moves bytes between one [`HostLink`] and any byte stream that
//! implements [`Read`] and [`Write`] (a named pipe, a Unix or vsock socket, or an
//! in-memory stream in tests), with bounded buffers and bounded work per call (§3.2 lines
//! 2061–2071; VM-W06 line 2591; VM-P28 line 2803: "malformed/oversized IPC, incomplete
//! frames, slow peers ... remain bounded").
//!
//! Each [`LinkDriver::step`] writes what the link has queued, reads at most
//! `max_reads_per_step` chunks of at most `read_chunk_bytes` into the one read buffer and
//! feeds them to the link, then writes again. The driver holds at most one outbound frame
//! that the transport has not fully taken; the link's queues and its decoder keep their
//! own bounds. A read that would block or timed out, and an interrupted call, are not
//! failures; a read of zero bytes is the peer ending its stream; any other error, a write
//! that takes zero bytes and pending output that makes no progress for
//! `write_stall_timeout` fail the transport. Every end of the transport is a typed
//! [`TransportEvent`], and the link learns of it through [`HostLink::peer_closed`], which
//! turns a partial frame into a truncation. These bounds live in
//! [`StreamIo`](super::stream_io::StreamIo), which the sandbox host's session pump uses
//! too, over the link the host owns.
//!
//! Once the link closes, the driver reads nothing more. What it still writes is the
//! stream's close policy ([`StreamIo`], review finding R2): after an orderly close it
//! drains the one frame it had already taken, bounded by `write_stall_timeout`, then the
//! link's close frame, and finishes with [`TransportEnd::LinkClosed`]; after every other
//! close it submits no old application bytes: an unwritten taken frame is discarded
//! (`frames_discarded`) and only the close frame goes out, and a partly written frame
//! abandons the transport at once with [`TransportEnd::Aborted`], which states how many
//! bytes of that frame had reached the transport. The owner drops an abandoned transport,
//! so the peer sees the stream end inside a frame. [`HostLink`] itself drops every queued
//! frame at any close, so the frame in the driver's hands is the only pre-close output
//! the driver can still submit.
//!
//! What any writer can do (M06 carry-forward: "any writer admitted to the per-instance
//! transport can close that link"): the link judges framing and then the tag before
//! anything else, and a failure of either closes it. So any process that can write to
//! the transport can close the link: before the guest's hello with an oversized header,
//! a bad magic or any frame without the bound guest's tag, and afterwards by putting
//! such bytes into the stream. It can do nothing else: no unauthenticated byte produces a
//! request, a report or an open link. Restricting who may write to the transport (the
//! policies in [`pipe`](super::pipe), [`unix_socket`](super::unix_socket) and
//! [`vsock`](super::vsock)) is what keeps every other process from closing it; nothing in
//! the bytes tells which writer closed a link. A [`Closure`] records whether the guest's
//! hello had been accepted before the link closed.
//!
//! Recovery is a new connection driven by a new driver. [`LinkDriver::connect`] binds its
//! link to the nonce the host drew for that connection (§3.2 line 2067
//! "generation/connection binding"): the link's first frame is the challenge, both
//! sequences start at 1 again, and frames recorded on an earlier connection of the same
//! boot, the guest's hello among them, are refused as
//! [`RefusalReason::StaleConnection`](crate::sandbox::link::RefusalReason::StaleConnection)
//! and close the link (the tests pin this). The test-only `LinkDriver::new` keeps a link
//! with no challenge, on which frames recorded on an earlier such link of the boot are
//! still accepted; only this module's tests use it. How often a supervisor reconnects
//! after closures before authentication is decided outside this module.

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::Clock;
use crate::sandbox::link::{
    Channel, CloseCause, CloseReason, ConnectionNonce, ConsumeRefusal, HostLink, HostMessage,
    LimitsError, LinkBinding, LinkEvent, LinkLimits, LinkPhase, ReportBody, SendRefusal,
};

use super::stream_io::{FrameEnd, StreamIo, StreamStop, WriteStop};

/// The default read chunk: 16 KiB.
pub const DEFAULT_READ_CHUNK_BYTES: u32 = 16 * 1_024;
/// The largest read chunk a configuration may ask for: 1 MiB.
pub const MAX_READ_CHUNK_BYTES: u32 = 1 << 20;

/// How much work one call may do. `Default` holds the documented defaults;
/// [`DriverLimits::validate`] checks a configuration before it is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverLimits {
    /// The read buffer, and the most one read call may take: 16 KiB.
    pub read_chunk_bytes: u32,
    /// Read calls per step: 4. Reading stops early after a read that did not fill the
    /// buffer, so a blocking stream is not read again in the same step.
    pub max_reads_per_step: u32,
    /// Write calls per step or flush: 64. A frame that needs more continues in the next.
    pub max_writes_per_step: u32,
    /// How long pending output may make no progress before the transport fails: 5 s.
    pub write_stall_timeout: Duration,
}

impl Default for DriverLimits {
    fn default() -> Self {
        Self {
            read_chunk_bytes: DEFAULT_READ_CHUNK_BYTES,
            max_reads_per_step: 4,
            max_writes_per_step: 64,
            write_stall_timeout: Duration::from_secs(5),
        }
    }
}

/// Why driver limits were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "driver_limits_error", rename_all = "snake_case")]
pub enum DriverLimitsError {
    ReadChunk { read_chunk_bytes: u32, max: u32 },
    ZeroReads,
    ZeroWrites,
    ZeroStallTimeout,
}

impl fmt::Display for DriverLimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadChunk {
                read_chunk_bytes,
                max,
            } => write!(
                f,
                "read_chunk_bytes {read_chunk_bytes} is not between 1 and {max}"
            ),
            Self::ZeroReads => f.write_str("max_reads_per_step may not be zero"),
            Self::ZeroWrites => f.write_str("max_writes_per_step may not be zero"),
            Self::ZeroStallTimeout => f.write_str("write_stall_timeout may not be zero"),
        }
    }
}

impl std::error::Error for DriverLimitsError {}

impl DriverLimits {
    pub fn validate(&self) -> Result<(), DriverLimitsError> {
        if self.read_chunk_bytes == 0 || self.read_chunk_bytes > MAX_READ_CHUNK_BYTES {
            return Err(DriverLimitsError::ReadChunk {
                read_chunk_bytes: self.read_chunk_bytes,
                max: MAX_READ_CHUNK_BYTES,
            });
        }
        if self.max_reads_per_step == 0 {
            return Err(DriverLimitsError::ZeroReads);
        }
        if self.max_writes_per_step == 0 {
            return Err(DriverLimitsError::ZeroWrites);
        }
        if self.write_stall_timeout.is_zero() {
            return Err(DriverLimitsError::ZeroStallTimeout);
        }
        Ok(())
    }
}

/// Why a driver could not be made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "driver_setup_error", rename_all = "snake_case")]
pub enum DriverSetupError {
    Link(LimitsError),
    Driver(DriverLimitsError),
}

impl fmt::Display for DriverSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Link(error) => write!(f, "link limits: {error}"),
            Self::Driver(error) => write!(f, "driver limits: {error}"),
        }
    }
}

impl std::error::Error for DriverSetupError {}

/// Which transport call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportOperation {
    Read,
    Write,
    Flush,
    /// Ending the stream in both directions after the last frame (the session pump).
    Shutdown,
}

/// What went wrong, from the I/O error kind or the driver's own checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    ConnectionReset,
    ConnectionAborted,
    BrokenPipe,
    NotConnected,
    UnexpectedEnd,
    PermissionDenied,
    /// A write took zero bytes of a non-empty frame.
    WriteZero,
    /// Pending output made no progress for the stall timeout.
    Stalled,
    Other,
}

impl FailureKind {
    pub(super) fn of(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::ConnectionReset => Self::ConnectionReset,
            ErrorKind::ConnectionAborted => Self::ConnectionAborted,
            ErrorKind::BrokenPipe => Self::BrokenPipe,
            ErrorKind::NotConnected => Self::NotConnected,
            ErrorKind::UnexpectedEof => Self::UnexpectedEnd,
            ErrorKind::PermissionDenied => Self::PermissionDenied,
            ErrorKind::WriteZero => Self::WriteZero,
            _ => Self::Other,
        }
    }
}

/// A failed transport call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct TransportFailure {
    pub operation: TransportOperation,
    pub kind: FailureKind,
    /// The operating system's error code, when the error carried one.
    pub os_error: Option<i32>,
}

impl TransportFailure {
    pub fn io(operation: TransportOperation, error: &io::Error) -> Self {
        Self {
            operation,
            kind: FailureKind::of(error.kind()),
            os_error: error.raw_os_error(),
        }
    }

    pub(super) const fn own(operation: TransportOperation, kind: FailureKind) -> Self {
        Self {
            operation,
            kind,
            os_error: None,
        }
    }
}

impl fmt::Display for TransportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport {:?} failed: {:?}", self.operation, self.kind)?;
        if let Some(code) = self.os_error {
            write!(f, " (os error {code})")?;
        }
        Ok(())
    }
}

impl std::error::Error for TransportFailure {}

/// How the driver finished with the transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "end", rename_all = "snake_case")]
pub enum TransportEnd {
    /// The link closed and every frame it held reached the transport.
    LinkClosed,
    /// The peer ended its stream; the link's close frame was offered to the transport.
    PeerEnded,
    /// A call failed or a write stalled; nothing more was read or written.
    Failed { failure: TransportFailure },
    /// The link closed for `reason`, which drains nothing, while a frame was partly
    /// written: `written` of its `of` bytes had reached the transport and cannot be
    /// recalled, the rest and the close frame were never written, and the transport is
    /// to be dropped. The peer sees the stream end inside a frame.
    Aborted {
        reason: CloseReason,
        written: usize,
        of: usize,
    },
    /// The owner ended the stream before the link finished with it (a launch that failed
    /// after the stream was connected, a service shutting down): the stream was shut down
    /// and nothing more was written or read.
    Abandoned,
}

/// What happened to the transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum TransportEvent {
    /// A read returned no bytes: the peer will send nothing more.
    PeerEnded,
    Failed {
        failure: TransportFailure,
    },
    /// The driver is done; the transport is not used again.
    Finished {
        end: TransportEnd,
    },
}

/// What one driver call produced, in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", content = "event", rename_all = "snake_case")]
pub enum DriverEvent {
    Link(LinkEvent),
    Transport(TransportEvent),
}

/// The driver's phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum DriverPhase {
    Running,
    /// The link closed; its last frames are being written and nothing is read. After an
    /// orderly close that is the frame already taken and the close frame, within the
    /// write stall timeout; after any other close only the close frame (module
    /// documentation).
    Draining,
    Finished {
        end: TransportEnd,
    },
}

/// How a finished driver's link ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Closure {
    pub cause: CloseCause,
    /// Whether the guest's hello had been accepted before the link closed.
    pub authenticated: bool,
    pub end: TransportEnd,
}

impl Closure {
    /// The link closed before the guest's hello was accepted.
    pub fn before_authentication(&self) -> bool {
        !self.authenticated
    }
}

/// Bytes and calls so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DriverCounters {
    pub read_calls: u64,
    pub bytes_read: u64,
    pub write_calls: u64,
    pub bytes_written: u64,
    pub frames_written: u64,
    /// Frames taken from the link and dropped unwritten because the link closed for a
    /// reason that drains nothing (module documentation).
    pub frames_discarded: u64,
}

impl DriverCounters {
    /// Whether bytes or frames moved since `before`. The call counts are not progress: a
    /// non-blocking read that would block is a call that moved nothing, and a driver that
    /// treated it as movement never slept (measured 30 October 2026: 1.4 million reads in
    /// four seconds on an idle link).
    pub fn progressed_since(&self, before: &Self) -> bool {
        self.bytes_read != before.bytes_read
            || self.bytes_written != before.bytes_written
            || self.frames_written != before.frames_written
            || self.frames_discarded != before.frames_discarded
    }
}

/// Drives one host link over one transport.
pub struct LinkDriver<C: Clock + Clone, T: Read + Write> {
    link: HostLink<C>,
    clock: C,
    io: StreamIo<T>,
    phase: DriverPhase,
    authenticated: bool,
    close_reported: bool,
}

impl<C: Clock + Clone, T: Read + Write> LinkDriver<C, T> {
    /// A new link bound to `binding` and to no connection (the test-only `HostLink::new`)
    /// under `link_limits`, driven over `transport` under `limits`, both on `clock`; both
    /// sets of limits are validated first. It exists only in test builds, for this
    /// module's tests (`link_transport/tests.rs`); every other driver binds its connection
    /// with [`LinkDriver::connect`].
    #[cfg(test)]
    pub(crate) fn new(
        binding: LinkBinding,
        link_limits: LinkLimits,
        limits: DriverLimits,
        clock: C,
        transport: T,
    ) -> Result<Self, DriverSetupError> {
        limits.validate().map_err(DriverSetupError::Driver)?;
        let link =
            HostLink::new(binding, link_limits, clock.clone()).map_err(DriverSetupError::Link)?;
        Self::over(link, limits, clock, transport)
    }

    /// A new link for one new connection, bound to `binding` and to `nonce`
    /// ([`HostLink::connect`]) under `link_limits`, driven over `transport` under
    /// `limits`, both on `clock`; both sets of limits are validated first. The first
    /// step writes the challenge.
    pub fn connect(
        binding: LinkBinding,
        nonce: ConnectionNonce,
        link_limits: LinkLimits,
        limits: DriverLimits,
        clock: C,
        transport: T,
    ) -> Result<Self, DriverSetupError> {
        limits.validate().map_err(DriverSetupError::Driver)?;
        let link = HostLink::connect(binding, nonce, link_limits, clock.clone())
            .map_err(DriverSetupError::Link)?;
        Self::over(link, limits, clock, transport)
    }

    fn over(
        link: HostLink<C>,
        limits: DriverLimits,
        clock: C,
        transport: T,
    ) -> Result<Self, DriverSetupError> {
        let io = StreamIo::new(transport, limits, clock.now()).map_err(DriverSetupError::Driver)?;
        Ok(Self {
            link,
            clock,
            io,
            phase: DriverPhase::Running,
            authenticated: false,
            close_reported: false,
        })
    }

    pub fn link(&self) -> &HostLink<C> {
        &self.link
    }

    #[cfg(test)]
    pub(crate) fn link_mut(&mut self) -> &mut HostLink<C> {
        &mut self.link
    }

    pub fn limits(&self) -> &DriverLimits {
        self.io.limits()
    }

    pub fn phase(&self) -> DriverPhase {
        self.phase
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.phase, DriverPhase::Finished { .. })
    }

    /// Whether the guest's hello has been accepted on this link.
    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn counters(&self) -> DriverCounters {
        self.io.counters()
    }

    /// Bytes of the pending frame the transport has not taken yet; never more than one
    /// frame.
    pub fn pending_output_bytes(&self) -> usize {
        self.io.pending_output_bytes()
    }

    /// How the link ended, once the driver has finished.
    pub fn closure(&self) -> Option<Closure> {
        let DriverPhase::Finished { end } = self.phase else {
            return None;
        };
        let LinkPhase::Closed(cause) = self.link.phase() else {
            return None;
        };
        Some(Closure {
            cause: cause.clone(),
            authenticated: self.authenticated,
            end,
        })
    }

    pub fn transport(&self) -> &T {
        self.io.transport()
    }

    pub fn into_transport(self) -> T {
        self.io.into_transport()
    }

    /// Queues a message for the guest ([`HostLink::send`]); the next step, flush or tick
    /// writes it. A close also closes the link.
    pub fn send(&mut self, message: HostMessage) -> Result<(), SendRefusal> {
        if self.is_finished() {
            return Err(SendRefusal::LinkClosed);
        }
        self.link.send(message)
    }

    /// Credits consumed bulk bytes back to the guest ([`HostLink::consume`]).
    pub fn consume(&mut self, channel: Channel, bytes: u32) -> Result<(), ConsumeRefusal> {
        self.link.consume(channel, bytes)
    }

    /// Writes what the link holds, reads and feeds at most the configured chunks, and
    /// writes again. Nothing is read once the link has closed, whenever it closed.
    pub fn step(&mut self) -> Vec<DriverEvent> {
        let mut events = Vec::new();
        if self.is_finished() {
            return events;
        }
        self.write_out(&mut events);
        self.settle(&mut events);
        if matches!(self.phase, DriverPhase::Running) {
            self.read_in(&mut events);
        }
        self.write_out(&mut events);
        self.settle(&mut events);
        events
    }

    /// Writes what the link holds, without reading.
    pub fn flush(&mut self) -> Vec<DriverEvent> {
        let mut events = Vec::new();
        self.write_out(&mut events);
        self.settle(&mut events);
        events
    }

    /// Applies the link's timeouts ([`HostLink::tick`]) and the write stall timeout at
    /// the clock's current time, then writes.
    pub fn tick(&mut self) -> Vec<DriverEvent> {
        let mut events = Vec::new();
        if self.is_finished() {
            return events;
        }
        let link_events = self.link.tick();
        self.record(link_events, &mut events);
        self.write_out(&mut events);
        self.settle(&mut events);
        events
    }

    fn read_in(&mut self, events: &mut Vec<DriverEvent>) {
        let stop = {
            let mut end = DriverEnd {
                link: &mut self.link,
                events: &mut *events,
                authenticated: &mut self.authenticated,
                close_reported: &mut self.close_reported,
            };
            self.io.read(&mut end)
        };
        match stop {
            None => {}
            Some(StreamStop::PeerEnded) => {
                events.push(DriverEvent::Transport(TransportEvent::PeerEnded));
                let link_events = self.link.peer_closed();
                self.record(link_events, events);
            }
            Some(StreamStop::Failed(failure)) => self.fail(failure, events),
        }
    }

    fn write_out(&mut self, events: &mut Vec<DriverEvent>) {
        if self.is_finished() {
            return;
        }
        let now = self.clock.now();
        let stop = {
            let mut end = DriverEnd {
                link: &mut self.link,
                events: &mut *events,
                authenticated: &mut self.authenticated,
                close_reported: &mut self.close_reported,
            };
            self.io.write(&mut end, now)
        };
        match stop {
            None => {}
            Some(WriteStop::Failed(failure)) => self.fail(failure, events),
            Some(WriteStop::Aborted {
                reason,
                written,
                of,
            }) => {
                // The link closed already and reported it; the transport is abandoned.
                self.report_close(events);
                self.finish(
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

    /// A transport call failed: the link learns the peer is gone and the driver finishes.
    fn fail(&mut self, failure: TransportFailure, events: &mut Vec<DriverEvent>) {
        events.push(DriverEvent::Transport(TransportEvent::Failed { failure }));
        self.io.drop_pending();
        let link_events = self.link.peer_closed();
        self.record(link_events, events);
        self.report_close(events);
        let end = if self.io.input_ended() {
            TransportEnd::PeerEnded
        } else {
            TransportEnd::Failed { failure }
        };
        self.finish(end, events);
    }

    /// Passes the link's events on (see [`record`]).
    fn record(&mut self, link_events: Vec<LinkEvent>, events: &mut Vec<DriverEvent>) {
        record(
            &mut self.authenticated,
            &mut self.close_reported,
            link_events,
            events,
        );
    }

    /// A link that closed without saying so (a host close) is reported once as the
    /// link's own close event; the link reports a used-up sequence itself.
    fn report_close(&mut self, events: &mut Vec<DriverEvent>) {
        if self.close_reported {
            return;
        }
        if let LinkPhase::Closed(cause) = self.link.phase() {
            events.push(DriverEvent::Link(LinkEvent::Closed(cause.clone())));
            self.close_reported = true;
        }
    }

    fn settle(&mut self, events: &mut Vec<DriverEvent>) {
        if self.is_finished() || !self.link.is_closed() {
            return;
        }
        self.report_close(events);
        self.phase = DriverPhase::Draining;
        if !self.io.has_pending() && self.link.queued_frames() == 0 {
            let end = if self.io.input_ended() {
                TransportEnd::PeerEnded
            } else {
                TransportEnd::LinkClosed
            };
            self.finish(end, events);
        }
    }

    fn finish(&mut self, end: TransportEnd, events: &mut Vec<DriverEvent>) {
        self.phase = DriverPhase::Finished { end };
        events.push(DriverEvent::Transport(TransportEvent::Finished { end }));
    }
}

/// Passes a link's events on. The accepted hello's report marks the link authenticated,
/// even when a violation in the same bytes closed it again; a close event is noted so it
/// is not reported twice.
fn record(
    authenticated: &mut bool,
    close_reported: &mut bool,
    link_events: Vec<LinkEvent>,
    events: &mut Vec<DriverEvent>,
) {
    for event in link_events {
        match &event {
            LinkEvent::Closed(_) => *close_reported = true,
            LinkEvent::Report(report) if matches!(report.body(), ReportBody::Hello(_)) => {
                *authenticated = true;
            }
            _ => {}
        }
        events.push(DriverEvent::Link(event));
    }
}

/// The driver's link as the link side of one pass of its stream.
struct DriverEnd<'a, C: Clock> {
    link: &'a mut HostLink<C>,
    events: &'a mut Vec<DriverEvent>,
    authenticated: &'a mut bool,
    close_reported: &'a mut bool,
}

impl<C: Clock> FrameEnd for DriverEnd<'_, C> {
    fn receive(&mut self, bytes: &[u8]) {
        let link_events = self.link.receive(bytes);
        record(
            self.authenticated,
            self.close_reported,
            link_events,
            self.events,
        );
    }

    fn stops_reading(&self) -> bool {
        self.link.is_closed()
    }

    fn next_frame(&mut self) -> Option<Vec<u8>> {
        let frame = self.link.next_outbound();
        if frame.is_none() {
            // A used-up sequence closes the link here, and the link returns that close
            // as its event.
            let link_events = self.link.take_events();
            record(
                self.authenticated,
                self.close_reported,
                link_events,
                self.events,
            );
        }
        frame
    }

    fn close_reason(&self) -> Option<CloseReason> {
        match self.link.phase() {
            LinkPhase::Closed(cause) => Some(cause.close_reason()),
            _ => None,
        }
    }
}

impl<C: Clock + Clone, T: Read + Write> fmt::Debug for LinkDriver<C, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkDriver")
            .field("link", &self.link)
            .field("phase", &self.phase)
            .field("authenticated", &self.authenticated)
            .field("pending_output_bytes", &self.pending_output_bytes())
            .field("counters", &self.io.counters())
            .finish()
    }
}
