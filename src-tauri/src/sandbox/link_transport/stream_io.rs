//! The bounded input and output of one byte stream, shared by the link driver
//! ([`LinkDriver`](super::LinkDriver)) and the sandbox host's session pump
//! (`sandbox::host::SessionPump`), so both carry a link over a stream with the same
//! bounds (§3.2 lines 2061–2071; VM-W06 line 2591; VM-P28 line 2803: "malformed/oversized
//! IPC, incomplete frames, slow peers ... remain bounded").
//!
//! One read buffer of `read_chunk_bytes`; at most `max_reads_per_step` reads per pass,
//! stopping early after a read that did not fill the buffer or once the link stops
//! reading; at most one outbound frame held that the stream has not fully taken, taken
//! from the link only when it can be written now; at most `max_writes_per_step` writes per
//! pass; and pending output that makes no progress for `write_stall_timeout` fails the
//! stream. A read that would block or timed out, and an interrupted call, are not
//! failures; a read of zero bytes is the peer ending its stream; any other error and a
//! write that takes zero bytes fail it. What the stream's end means for the link is the
//! caller's: [`FrameEnd`] is the link side of one pass.
//!
//! The close policy (review finding R2, docs/manager-work-split/reviewer-findings.md) is
//! applied here, once per closure, before any byte of a frame taken before the close is
//! submitted: the link side says why it closed ([`FrameEnd::close_reason`]). An orderly
//! close ([`CloseReason::Orderly`]: the host's own orderly close, the guest's close, a
//! disconnected peer, an exhausted sequence) drains the one frame already taken, bounded
//! by `write_stall_timeout`, then the close frame. Every other close (revocation,
//! shutdown, a protocol violation, a timeout) submits no old application bytes: a taken
//! frame none of whose bytes the stream accepted is discarded (counted in
//! `frames_discarded`) and only the close frame goes out; a frame the stream partly
//! accepted cannot be recalled and must not be followed by a close frame in its middle,
//! so the stream is abandoned ([`WriteStop::Aborted`]: how many bytes of that frame had
//! reached it) and nothing more is written. Frames taken after the close (the close
//! frame itself) are not subject to the policy.

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};

use crate::foundation::ids::MonotonicTime;
use crate::sandbox::link::CloseReason;

use super::driver::{
    DriverCounters, DriverLimits, DriverLimitsError, FailureKind, TransportFailure,
    TransportOperation,
};

/// The link side of one pass of a [`StreamIo`]: it takes the bytes read and gives the
/// frames to write.
pub trait FrameEnd {
    /// Takes bytes read from the stream, in order.
    fn receive(&mut self, bytes: &[u8]);

    /// Whether no more bytes may be read: the link closed, or the host closed the
    /// channels it belongs to.
    fn stops_reading(&self) -> bool;

    /// The next frame to write, sealed; called only when the stream can take it now, so a
    /// frame leaves the link's queue only then.
    fn next_frame(&mut self) -> Option<Vec<u8>>;

    /// Why the link side closed, once it did: the reason its close frame carries. `None`
    /// while it is open. The stream applies the close policy (module docs) to the frame it
    /// took before the close the first time this is `Some`.
    fn close_reason(&self) -> Option<CloseReason>;
}

/// A byte stream the host ends in both directions once it wrote its last frame (a
/// socket's `shutdown` of both directions). The session pump calls it once.
pub trait StreamShutdown {
    fn shut_down(&mut self) -> io::Result<()>;
}

/// How a read pass ended the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamStop {
    /// A read returned no bytes: the peer will send nothing more.
    PeerEnded,
    /// A read failed.
    Failed(TransportFailure),
}

/// How a write pass ended the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteStop {
    /// A write failed: pending output stalled past the timeout, a write of zero bytes, or
    /// an error other than an interruption, a would-block or a timeout.
    Failed(TransportFailure),
    /// The link closed for `reason`, which drains nothing, while a frame was partly
    /// written: `written` of its `of` bytes had reached the stream and cannot be
    /// recalled; the rest and the close frame were never written, and the stream is to
    /// be abandoned (module docs).
    Aborted {
        reason: CloseReason,
        written: usize,
        of: usize,
    },
}

/// Whether a close for `reason` drains the frame the stream already took from the link
/// (module docs): only an orderly close does.
pub const fn drains(reason: CloseReason) -> bool {
    matches!(reason, CloseReason::Orderly)
}

/// The one outbound frame the stream has not fully taken.
struct PendingFrame {
    bytes: Vec<u8>,
    written: usize,
}

/// The bounded input and output of one byte stream (module docs).
pub struct StreamIo<T: Read + Write> {
    transport: T,
    limits: DriverLimits,
    read_buffer: Vec<u8>,
    pending: Option<PendingFrame>,
    last_progress: MonotonicTime,
    input_ended: bool,
    /// Whether the close policy was applied to the frame taken before the link closed.
    close_handled: bool,
    counters: DriverCounters,
}

impl<T: Read + Write> StreamIo<T> {
    /// The input and output of `transport` under `limits`, which are validated first,
    /// started at `now`.
    pub fn new(
        transport: T,
        limits: DriverLimits,
        now: MonotonicTime,
    ) -> Result<Self, DriverLimitsError> {
        limits.validate()?;
        let read_chunk =
            usize::try_from(limits.read_chunk_bytes).map_err(|_| DriverLimitsError::ReadChunk {
                read_chunk_bytes: limits.read_chunk_bytes,
                max: super::driver::MAX_READ_CHUNK_BYTES,
            })?;
        Ok(Self {
            transport,
            limits,
            read_buffer: vec![0; read_chunk],
            pending: None,
            last_progress: now,
            input_ended: false,
            close_handled: false,
            counters: DriverCounters::default(),
        })
    }

    pub fn limits(&self) -> &DriverLimits {
        &self.limits
    }

    pub fn counters(&self) -> DriverCounters {
        self.counters
    }

    /// Whether a read returned no bytes.
    pub fn input_ended(&self) -> bool {
        self.input_ended
    }

    /// Whether a frame is held that the stream has not fully taken.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Bytes of the pending frame the stream has not taken yet; never more than one
    /// frame.
    pub fn pending_output_bytes(&self) -> usize {
        self.pending.as_ref().map_or(0, |pending| {
            pending.bytes.len().saturating_sub(pending.written)
        })
    }

    /// Drops the pending frame: the stream failed and nothing more is written.
    pub fn drop_pending(&mut self) {
        self.pending = None;
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Reads at most the configured chunks and gives each to `end`. Returns how the
    /// stream ended, if it did in this pass.
    pub fn read(&mut self, end: &mut impl FrameEnd) -> Option<StreamStop> {
        for _ in 0..self.limits.max_reads_per_step {
            self.counters.read_calls += 1;
            match self.transport.read(&mut self.read_buffer) {
                Ok(0) => {
                    self.input_ended = true;
                    return Some(StreamStop::PeerEnded);
                }
                Ok(count) => {
                    let count = count.min(self.read_buffer.len());
                    self.counters.bytes_read += count as u64;
                    end.receive(self.read_buffer.get(..count).unwrap_or_default());
                    if end.stops_reading() || count < self.read_buffer.len() {
                        return None;
                    }
                }
                Err(error) => match error.kind() {
                    ErrorKind::Interrupted => {}
                    ErrorKind::WouldBlock | ErrorKind::TimedOut => return None,
                    _ => {
                        return Some(StreamStop::Failed(TransportFailure::io(
                            TransportOperation::Read,
                            &error,
                        )))
                    }
                },
            }
        }
        None
    }

    /// Applies the close policy (module docs), once per closure, to the frame in the
    /// stream's hands when the link side's closure is first seen here. Returns the abort
    /// that ends the stream, if the frame was partly written.
    fn discard_pre_close_output(&mut self, end: &impl FrameEnd) -> Option<WriteStop> {
        if self.close_handled {
            return None;
        }
        let reason = end.close_reason()?;
        self.close_handled = true;
        if drains(reason) {
            return None;
        }
        let pending = self.pending.take()?;
        if pending.written == 0 {
            self.counters.frames_discarded += 1;
            return None;
        }
        Some(WriteStop::Aborted {
            reason,
            written: pending.written,
            of: pending.bytes.len(),
        })
    }

    /// Writes the pending frame and then frames `end` gives, with at most the configured
    /// write calls, and flushes when anything was written. First applies the close policy
    /// to a frame taken before the link closed. Returns what ends the stream, if anything
    /// did in this pass: an abort under the close policy, or a failure (pending output
    /// stalled past the timeout, a write of zero bytes, or an error other than an
    /// interruption, a would-block or a timeout).
    pub fn write(&mut self, end: &mut impl FrameEnd, now: MonotonicTime) -> Option<WriteStop> {
        if let Some(stop) = self.discard_pre_close_output(end) {
            return Some(stop);
        }
        if self.pending.is_some()
            && now.saturating_duration_since(self.last_progress) > self.limits.write_stall_timeout
        {
            return Some(WriteStop::Failed(TransportFailure::own(
                TransportOperation::Write,
                FailureKind::Stalled,
            )));
        }
        let mut wrote = false;
        let mut calls = 0u32;
        while calls < self.limits.max_writes_per_step {
            // A frame leaves the link's queue only when it can be written now.
            if self.pending.is_none() {
                let Some(bytes) = end.next_frame() else {
                    break;
                };
                self.pending = Some(PendingFrame { bytes, written: 0 });
                self.last_progress = now;
            }
            calls += 1;
            self.counters.write_calls += 1;
            let outcome = match &self.pending {
                Some(pending) => {
                    let rest = pending.bytes.get(pending.written..).unwrap_or_default();
                    self.transport
                        .write(rest)
                        .map(|count| count.min(rest.len()))
                }
                None => break,
            };
            match outcome {
                Ok(0) => {
                    return Some(WriteStop::Failed(TransportFailure::own(
                        TransportOperation::Write,
                        FailureKind::WriteZero,
                    )))
                }
                Ok(count) => {
                    wrote = true;
                    self.advance(count, now);
                }
                Err(error) => match error.kind() {
                    ErrorKind::Interrupted => {}
                    ErrorKind::WouldBlock | ErrorKind::TimedOut => break,
                    _ => {
                        return Some(WriteStop::Failed(TransportFailure::io(
                            TransportOperation::Write,
                            &error,
                        )));
                    }
                },
            }
        }
        if wrote {
            if let Err(error) = self.transport.flush() {
                if !matches!(
                    error.kind(),
                    ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
                ) {
                    return Some(WriteStop::Failed(TransportFailure::io(
                        TransportOperation::Flush,
                        &error,
                    )));
                }
            }
        }
        None
    }

    fn advance(&mut self, count: usize, now: MonotonicTime) {
        self.counters.bytes_written += count as u64;
        self.last_progress = now;
        let done = match self.pending.as_mut() {
            Some(pending) => {
                pending.written += count;
                pending.written >= pending.bytes.len()
            }
            None => false,
        };
        if done {
            self.pending = None;
            self.counters.frames_written += 1;
        }
    }
}

impl<T: Read + Write> fmt::Debug for StreamIo<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamIo")
            .field("limits", &self.limits)
            .field("pending_output_bytes", &self.pending_output_bytes())
            .field("input_ended", &self.input_ended)
            .field("counters", &self.counters)
            .finish()
    }
}
