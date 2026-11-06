//! A sandbox's ingress streams as the service lends them out (M14; module docs in `mod.rs`):
//! [`VmService::ingress`](super::VmService::ingress) returns a [`GuestIngress`] for a guest
//! listener, the guest end of one caller's session for the connection gate
//! ([`SessionStream`]).
//!
//! The stream opens on the link only once the gate first reads or writes the handle, which it
//! does only for a caller it admitted: a caller it refuses has the handle closed untouched, so
//! the guest is never asked to connect for it. The handle never takes the service's lock: it
//! shares a small buffer with the boot's driver, which on every pass opens a touched request,
//! hands what the caller wrote to the link within the stream's pending bound, and the guest
//! service's bytes, its end and the stream's end to the buffer. The guest's bytes are
//! credited back to their stream only as the caller takes them, and the handle gives the gate
//! no more than the caller's side has room for ([`GuestIngress::set_caller_room`]), so the
//! guest is slowed to its caller's pace end to end, a caller that stops reading stops only
//! its own stream (each stream has a window of its own), and the buffer stays within the
//! stream's window ([`MAX_INBOUND_BYTES`], which the link already refuses a guest to pass). A closed handle has the stream cancelled on the link; a stream the guest
//! refused, cancelled or that the host closed (a revocation, a stop) fails the handle's next
//! read or write. A finished handle (a half close) has the host's direction ended on the
//! link once every byte written before went out; closed after finishing, it is flushed and
//! ended rather than cancelled, and what the guest sends afterwards is credited back unread.
//!
//! The same buffer carries the caller's end of a sandbox connection (M14, module docs in
//! `connect`): the stream the caller's guest opened on its egress channel to a connection
//! endpoint, accepted at once ([`IngressShared::accepted`]); its driver moves it over the
//! egress channel instead. Closed, that end is never cut short of what passed the gate: once
//! the gate wrote it anything, it is flushed and ended (its program reads to the end of what
//! passed, then the end of the stream); one the gate never wrote to (a refused connection)
//! is cancelled.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use serde::Serialize;

use crate::sandbox::host::IngressEndCause;
use crate::sandbox::link::{LinkName, OpenRefusalCause, StreamId};
use crate::sandbox_contract::connections::{SessionStream, StreamError, StreamRead};

/// The most of the guest service's bytes one stream holds for its caller: the most a
/// stream's window grows to, which the link refuses the guest to pass.
pub const MAX_INBOUND_BYTES: usize = crate::sandbox::link::MAX_STREAM_WINDOW_BYTES as usize;

/// The most of the caller's bytes one stream holds before the driver hands them to the link.
pub const MAX_OUTBOUND_BYTES: usize = 1 << 20;

/// Where one ingress stream stands.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    /// Not opened on the link yet; `touched` once the gate read or wrote the handle.
    Requested { touched: bool },
    /// Opened on the link; the guest has not answered.
    Opening,
    Open,
    /// The stream is gone; the detail says why.
    Closed { detail: String },
}

#[derive(Debug)]
struct Buffers {
    phase: Phase,
    stream: Option<StreamId>,
    /// The guest service's bytes, not taken by the caller yet.
    inbound: VecDeque<u8>,
    /// The guest ended its direction.
    guest_ended: bool,
    /// The caller's bytes, not handed to the link yet.
    outbound: VecDeque<u8>,
    /// The caller closed its end: the driver cancels the stream, or never opens it (or,
    /// after a finish, flushes and ends it).
    close_requested: bool,
    /// The caller ended its writing; the host's direction ends once `outbound` went out.
    finish_requested: bool,
    finish_sent: bool,
    /// The gate wrote the stream something, ever.
    written: bool,
    /// The guest's bytes received and not credited back yet, and of those the ones the
    /// caller took; once the stream ended every byte left is credited at once.
    uncredited: usize,
    credit_due: usize,
    credit_released: bool,
}

/// What the driver is to do with a request this pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RequestStep {
    /// Not touched yet: wait.
    Wait,
    /// Touched: open it on the link now.
    Open,
    /// Closed before it opened: forget it.
    Drop,
}

/// What the driver is to do with an open stream's caller side this pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Outbound {
    /// The caller's bytes for the link.
    pub(super) bytes: Vec<u8>,
    /// The caller closed without finishing: cancel the stream.
    pub(super) cancel: bool,
    /// Every byte went out after the caller finished: end the host's direction (once).
    pub(super) finish: bool,
}

/// The buffer a [`GuestIngress`] shares with its boot's driver.
#[derive(Debug)]
pub(super) struct IngressShared {
    listener: LinkName,
    /// A sandbox connection's caller end: closed after the gate wrote it anything, it is
    /// flushed and ended rather than cancelled.
    orderly_close: bool,
    buffers: Mutex<Buffers>,
}

impl IngressShared {
    pub(super) fn new(listener: LinkName) -> Arc<Self> {
        Self::with(listener, Phase::Requested { touched: false }, None, false)
    }

    /// A stream the guest opened and the host accepted, named `destination` (the caller's
    /// end of a sandbox connection, on its egress channel).
    pub(super) fn accepted(stream: StreamId, destination: LinkName) -> Arc<Self> {
        Self::with(destination, Phase::Open, Some(stream), true)
    }

    fn with(
        listener: LinkName,
        phase: Phase,
        stream: Option<StreamId>,
        orderly_close: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            listener,
            orderly_close,
            buffers: Mutex::new(Buffers {
                phase,
                stream,
                inbound: VecDeque::new(),
                guest_ended: false,
                outbound: VecDeque::new(),
                close_requested: false,
                finish_requested: false,
                finish_sent: false,
                written: false,
                uncredited: 0,
                credit_due: 0,
                credit_released: false,
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Buffers> {
        self.buffers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn listener(&self) -> &LinkName {
        &self.listener
    }

    /// What the driver is to do with this request now.
    pub(super) fn request_step(&self) -> RequestStep {
        let buffers = self.lock();
        match buffers.phase {
            _ if buffers.close_requested => RequestStep::Drop,
            Phase::Requested { touched: true } => RequestStep::Open,
            Phase::Requested { touched: false } => RequestStep::Wait,
            _ => RequestStep::Drop,
        }
    }

    /// The stream was opened on the link as `stream`.
    pub(super) fn opening(&self, stream: StreamId) {
        let mut buffers = self.lock();
        buffers.stream = Some(stream);
        if matches!(buffers.phase, Phase::Requested { .. }) {
            buffers.phase = Phase::Opening;
        }
    }

    /// The guest's service accepted the stream.
    pub(super) fn opened(&self) {
        let mut buffers = self.lock();
        if buffers.phase == Phase::Opening {
            buffers.phase = Phase::Open;
        }
    }

    /// The guest service's bytes; `false` when the stream holds [`MAX_INBOUND_BYTES`]
    /// already, and the driver cancels it.
    pub(super) fn received(&self, bytes: &[u8]) -> bool {
        let mut buffers = self.lock();
        if buffers.close_requested {
            // Nobody reads a closed handle: the bytes go back as credit at once.
            if !buffers.credit_released {
                buffers.uncredited += bytes.len();
                buffers.credit_due += bytes.len();
            }
            return true;
        }
        if buffers.inbound.len().saturating_add(bytes.len()) > MAX_INBOUND_BYTES {
            return false;
        }
        buffers.inbound.extend(bytes);
        if !buffers.credit_released {
            buffers.uncredited += bytes.len();
        }
        true
    }

    /// The bytes the caller took since the last call: their credit is due to the guest.
    pub(super) fn take_credit_due(&self) -> usize {
        let mut buffers = self.lock();
        let due = std::mem::take(&mut buffers.credit_due);
        buffers.uncredited = buffers.uncredited.saturating_sub(due);
        due
    }

    /// Stops counting credit: the stream ended, so no more of its bytes come and its window
    /// went with it; what it left waits for its caller. Returns the bytes not credited.
    pub(super) fn release_credit(&self) -> usize {
        let mut buffers = self.lock();
        buffers.credit_released = true;
        buffers.credit_due = 0;
        std::mem::take(&mut buffers.uncredited)
    }

    /// The guest ended its direction.
    pub(super) fn guest_ended(&self) {
        self.lock().guest_ended = true;
    }

    /// The stream is gone (or never opened) for `detail`. Bytes the guest sent before stay
    /// readable.
    pub(super) fn ended(&self, detail: String) {
        let mut buffers = self.lock();
        if !matches!(buffers.phase, Phase::Closed { .. }) {
            buffers.phase = Phase::Closed { detail };
        }
    }

    /// At most `room` of the caller's bytes for the link, when the stream is open; whether
    /// the caller closed its end without finishing; and whether its finish is due now.
    pub(super) fn take_outbound(&self, room: usize) -> Outbound {
        let mut buffers = self.lock();
        // Closed without finishing: cancelled, unless it is a connection's caller end the gate
        // wrote anything, which gets what passed and then its end.
        let orderly = self.orderly_close && buffers.written;
        if buffers.close_requested && !buffers.finish_requested && !orderly {
            return Outbound {
                cancel: true,
                ..Outbound::default()
            };
        }
        let finishing = buffers.finish_requested || buffers.close_requested;
        let open = buffers.phase == Phase::Open;
        let take = if open {
            buffers.outbound.len().min(room)
        } else {
            0
        };
        let bytes: Vec<u8> = buffers.outbound.drain(..take).collect();
        let finish = open
            && bytes.is_empty()
            && buffers.outbound.is_empty()
            && finishing
            && !buffers.finish_sent;
        if finish {
            buffers.finish_sent = true;
        }
        Outbound {
            bytes,
            cancel: false,
            finish,
        }
    }

    /// Puts `bytes` the link did not take back in front of the caller's.
    pub(super) fn untake(&self, bytes: Vec<u8>) {
        let mut buffers = self.lock();
        for byte in bytes.into_iter().rev() {
            buffers.outbound.push_front(byte);
        }
    }
}

/// Why the link ended an ingress stream, in words.
pub(super) fn end_detail(cause: &IngressEndCause) -> String {
    match cause {
        IngressEndCause::Finished => "the stream finished".to_owned(),
        IngressEndCause::GuestCancelled { cancel } => {
            format!("the guest cancelled the stream ({cancel:?})")
        }
        IngressEndCause::HostCancelled => "the host cancelled the stream".to_owned(),
        IngressEndCause::OpenTimedOut => "the guest did not answer the open in time".to_owned(),
        IngressEndCause::ChannelClosed { cause } => {
            format!("the ingress channel closed ({cause:?})")
        }
        IngressEndCause::LinkClosed { close } => format!("the link closed ({close:?})"),
        IngressEndCause::HostClosed { closure } => {
            format!("the host closed the sandbox's channels ({closure:?})")
        }
    }
}

/// Why the guest refused an open, in words.
pub(super) fn refusal_detail(cause: OpenRefusalCause) -> String {
    match cause {
        OpenRefusalCause::Unavailable => {
            "nothing listens on that guest port, or the guest takes no stream now".to_owned()
        }
        OpenRefusalCause::Unsupported => "the guest does not serve that listener".to_owned(),
        other => format!("the guest refused the stream ({other:?})"),
    }
}

/// How much the caller's side of a session takes now.
pub type CallerRoom = Arc<dyn Fn() -> usize + Send + Sync>;

/// The guest end of one caller's ingress stream, for the connection gate (module docs).
pub struct GuestIngress {
    shared: Arc<IngressShared>,
    caller_room: Option<CallerRoom>,
}

impl std::fmt::Debug for GuestIngress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestIngress")
            .field("shared", &self.shared)
            .finish_non_exhaustive()
    }
}

impl GuestIngress {
    pub(super) fn new(shared: Arc<IngressShared>) -> Self {
        Self {
            shared,
            caller_room: None,
        }
    }

    /// Reads no more of the guest's bytes than `room` says the caller's side takes now.
    pub fn set_caller_room(&mut self, room: CallerRoom) {
        self.caller_room = Some(room);
    }

    /// The stream on the link, once it was opened there.
    pub fn stream(&self) -> Option<StreamId> {
        self.shared.lock().stream
    }

    /// How many more of the caller's bytes the stream takes now: its caller reads no more
    /// than this, so a guest that does not read slows the caller down instead of failing it.
    pub fn room(&self) -> usize {
        MAX_OUTBOUND_BYTES.saturating_sub(self.shared.lock().outbound.len())
    }

    /// Whether the guest's service accepted the stream.
    pub fn is_open(&self) -> bool {
        self.shared.lock().phase == Phase::Open
    }

    /// Why the stream is gone, once it is.
    pub fn closed(&self) -> Option<String> {
        match &self.shared.lock().phase {
            Phase::Closed { detail } => Some(detail.clone()),
            _ => None,
        }
    }

    /// A second handle on the same stream (for the caller's side to read its room).
    pub fn watch(&self) -> GuestIngressWatch {
        GuestIngressWatch {
            shared: Arc::clone(&self.shared),
        }
    }
}

/// What the caller's side reads of a guest stream it does not own: its room.
#[derive(Clone, Debug)]
pub struct GuestIngressWatch {
    shared: Arc<IngressShared>,
}

impl GuestIngressWatch {
    /// See [`GuestIngress::room`].
    pub fn room(&self) -> usize {
        MAX_OUTBOUND_BYTES.saturating_sub(self.shared.lock().outbound.len())
    }

    /// A watch on a stream of no sandbox, always with all its room (tests of a caller's
    /// side).
    #[cfg(test)]
    pub fn unbounded_for_tests() -> Self {
        Self {
            shared: IngressShared::new(
                LinkName::new("port-1").unwrap_or_else(|_| unreachable!("a valid name")),
            ),
        }
    }
}

fn touch(buffers: &mut Buffers) {
    if let Phase::Requested { touched } = &mut buffers.phase {
        *touched = true;
    }
}

impl SessionStream for GuestIngress {
    fn read(&mut self, buffer: &mut [u8]) -> Result<StreamRead, StreamError> {
        // Asked before this stream's lock: the caller's side has a lock of its own.
        let room = self.caller_room.as_ref().map_or(usize::MAX, |room| room());
        let mut buffers = self.shared.lock();
        if buffers.close_requested {
            return Err(StreamError::Closed);
        }
        touch(&mut buffers);
        if !buffers.inbound.is_empty() {
            let take = buffers.inbound.len().min(buffer.len()).min(room);
            if take == 0 {
                return Ok(StreamRead::Idle);
            }
            for (slot, byte) in buffer.iter_mut().zip(buffers.inbound.drain(..take)) {
                *slot = byte;
            }
            if !buffers.credit_released {
                buffers.credit_due += take;
            }
            return Ok(StreamRead::Bytes(take));
        }
        if buffers.guest_ended {
            return Ok(StreamRead::Ended);
        }
        match &buffers.phase {
            Phase::Closed { detail } => Err(StreamError::Failed {
                detail: detail.clone(),
            }),
            _ => Ok(StreamRead::Idle),
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        let mut buffers = self.shared.lock();
        if buffers.close_requested || buffers.finish_requested {
            return Err(StreamError::Closed);
        }
        if let Phase::Closed { detail } = &buffers.phase {
            return Err(StreamError::Failed {
                detail: detail.clone(),
            });
        }
        if buffers.outbound.len().saturating_add(bytes.len()) > MAX_OUTBOUND_BYTES {
            return Err(StreamError::Failed {
                detail: format!(
                    "the guest's stream holds {} bytes it has not taken",
                    buffers.outbound.len()
                ),
            });
        }
        touch(&mut buffers);
        buffers.outbound.extend(bytes);
        buffers.written |= !bytes.is_empty();
        Ok(())
    }

    fn finish(&mut self) {
        let mut buffers = self.shared.lock();
        if !buffers.close_requested {
            touch(&mut buffers);
            buffers.finish_requested = true;
        }
    }

    fn close(&mut self) {
        self.shared.lock().close_requested = true;
    }
}

/// The ingress channel of a sandbox, as status shows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct IngressView {
    /// Ingress streams open on the link now.
    pub open_streams: usize,
    /// Callers' streams waiting to open.
    pub requested: usize,
    /// Streams opened on the link since the launch: each asked the guest to open a port.
    pub opened: u64,
}
