//! The host side of one link: authentication, generation, connection and sequence checks,
//! the handshake, per-channel streams, windows and quotas, control priority,
//! cancellation, timeouts and half-close (§3.2 lines 2063–2074, connection binding line
//! 2067; §2.6 line 2004; VM-P28 and VM-P29 lines 2803–2804; VM-R49, VM-R56, VM-R58,
//! VM-R59 and VM-R64 lines 2914–2929).
//!
//! Order of checks on every received frame: framing, tag, boot generation, connection,
//! sequence, operation, direction, channel state, message size, stream id, handshake
//! phase, payload fields, then stream and window state. A failure of the first five
//! closes the link (the bytes are not from the bound guest on this connection, or the
//! stream cannot be trusted any more); every later refusal drops the frame and counts
//! against the refusal budget, whose exhaustion closes the link; a window overrun closes
//! the channel.
//!
//! A link made with [`HostLink::connect`] is bound to one connection: its first frame is
//! a challenge with the host's [`ConnectionNonce`], and the guest's hello and every later
//! frame in both directions carry that nonce under the tag. A frame recorded on an
//! earlier connection of the same boot names that connection and is refused as
//! [`RefusalReason::StaleConnection`]; its tag cannot be moved to a frame that names this
//! one, because the tag covers the field. Sequences start at 1 on every link, so on every
//! connection. The test-only `HostLink::new` makes a link with no challenge, bound to
//! [`Connection::UNCHALLENGED`]: a guest's hello recorded on one such link is accepted by
//! the next one of the same boot, as before the connection binding.
//!
//! The guest's credit a queued data frame was charged is returned when the frame is
//! dropped by a cancel, and guest data that arrives for a cancelled stream counts against
//! the receive window and is credited straight back, so cancels never shrink a window.
//!
//! The ingress and egress channels are flow-controlled per stream (protocol version 3): each
//! of their streams is an independent connection, and with one window per channel a stream
//! whose reader stopped held the whole window and stalled the channel's other streams. Each
//! direction of such a stream starts with [`STREAM_WINDOW_BYTES`]; its data is charged to
//! that window alone and a `StreamWindowUpdate` credits it. A guest that sends more than a
//! stream's window closes the channel ([`RefusalReason::StreamWindowExceeded`]). The host
//! credits a stream as its bytes are consumed ([`HostLink::consume_stream`]), keeping what
//! the guest may send plus what the host holds at the stream's window: its first window, or,
//! once the stream consumed a whole first window, [`MAX_STREAM_WINDOW_BYTES`] while the
//! channel's streams grew past their first windows by no more than the channel's
//! buffered-byte quota (a stream's growth returns when it ends). So the host holds at most
//! `max_streams` first windows plus that quota per channel, and every stream keeps its own
//! first window whatever the others do: a stream whose reader stops stops only itself.
//! Credit for a stream both ends finished is dropped quietly (it may cross the finish).
//! A challenged link's handshake timeout starts when its challenge is sealed for the
//! transport, not when the link is made.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::Serialize;

use crate::foundation::ids::{Clock, MonotonicTime};

use super::connection::{Connection, ConnectionNonce};
use super::decoder::{DecodeStep, FrameDecoder, RawFrame};
use super::fields::EncodeRefusal;
use super::limits::{
    ChannelQuota, LimitsError, LinkLimits, MAX_STREAM_WINDOW_BYTES, STREAM_WINDOW_BYTES,
};
use super::messages::{
    CancelCause, Classified, CloseReason, GuestRequest, HostMessage, LinkMessage, PayloadRefusal,
    ReportBody, StreamId, WelcomeTerms,
};
use super::report::GuestReport;
use super::secret::LinkBinding;
use super::sequence::{SequenceRefusal, SequenceState};
use super::wire::{Channel, FrameHeader, FramingRefusal, Operation, Sender, PROTOCOL_VERSION};

/// Which claimed identity field disagreed with the binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimedField {
    Vm,
    Boot,
}

/// Why a received frame was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum RefusalReason {
    Framing(FramingRefusal),
    /// The tag is not the bound guest's for these bytes.
    Unauthenticated,
    /// The frame is bound to another boot generation than the link.
    StaleGeneration {
        frame: u64,
        bound: u64,
    },
    /// The frame names another connection than the link: it was recorded on an earlier
    /// connection of the boot, or sealed with no challenge for a challenged link, or
    /// with one for an unchallenged link.
    StaleConnection {
        frame: Connection,
        bound: Connection,
    },
    Sequence(SequenceRefusal),
    LinkAlreadyClosed,
    UnknownOperation {
        channel: Channel,
        code: u8,
    },
    /// A host-only operation sent by the guest: the guest tried to select a host action.
    WrongDirection {
        channel: Channel,
        operation: Operation,
    },
    ChannelClosed {
        channel: Channel,
    },
    MessageTooLarge {
        channel: Channel,
        payload_bytes: usize,
        max_message_bytes: u32,
    },
    HandshakeIncomplete {
        operation: Operation,
    },
    HandshakeRepeated,
    UnsupportedGuestVersion {
        version: u8,
    },
    /// The guest claims to be another VM or boot than the host bound the link to.
    ClaimedIdentityDisagrees {
        field: ClaimedField,
    },
    Payload(PayloadRefusal),
    /// The guest used a host-parity stream id.
    StreamParity {
        stream: StreamId,
    },
    /// Stream ids are never reused; a guest id must exceed every earlier one.
    StreamIdNotIncreasing {
        stream: StreamId,
        highest: u32,
    },
    StreamQuotaExceeded {
        channel: Channel,
        max_streams: u32,
    },
    StreamNotOpen {
        channel: Channel,
        stream: StreamId,
    },
    /// An opened or open-refused answer for a stream not awaiting the guest's answer.
    StreamNotOpening {
        channel: Channel,
        stream: StreamId,
    },
    StreamCancelled {
        channel: Channel,
        stream: StreamId,
    },
    /// Data or a second end-of-stream after the guest ended its direction.
    HalfClosed {
        channel: Channel,
        stream: StreamId,
    },
    WindowExceeded {
        channel: Channel,
        remaining_bytes: u64,
        needed_bytes: u64,
    },
    /// More data on an ingress or egress stream than its window allows.
    StreamWindowExceeded {
        channel: Channel,
        stream: StreamId,
        remaining_bytes: u64,
        needed_bytes: u64,
    },
}

impl RefusalReason {
    /// The stable name used by the conformance corpus.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Framing(refusal) => refusal.code(),
            Self::Unauthenticated => "unauthenticated",
            Self::StaleGeneration { .. } => "stale_generation",
            Self::StaleConnection { .. } => "stale_connection",
            Self::Sequence(refusal) => refusal.code(),
            Self::LinkAlreadyClosed => "link_already_closed",
            Self::UnknownOperation { .. } => "unknown_operation",
            Self::WrongDirection { .. } => "wrong_direction",
            Self::ChannelClosed { .. } => "channel_closed",
            Self::MessageTooLarge { .. } => "message_too_large",
            Self::HandshakeIncomplete { .. } => "handshake_incomplete",
            Self::HandshakeRepeated => "handshake_repeated",
            Self::UnsupportedGuestVersion { .. } => "unsupported_guest_version",
            Self::ClaimedIdentityDisagrees { .. } => "claimed_identity_disagrees",
            Self::Payload(refusal) => refusal.code(),
            Self::StreamParity { .. } => "stream_parity",
            Self::StreamIdNotIncreasing { .. } => "stream_id_not_increasing",
            Self::StreamQuotaExceeded { .. } => "stream_quota_exceeded",
            Self::StreamNotOpen { .. } => "stream_not_open",
            Self::StreamNotOpening { .. } => "stream_not_opening",
            Self::StreamCancelled { .. } => "stream_cancelled",
            Self::HalfClosed { .. } => "half_closed",
            Self::WindowExceeded { .. } => "window_exceeded",
            Self::StreamWindowExceeded { .. } => "stream_window_exceeded",
        }
    }
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Framing(refusal) => fmt::Display::fmt(refusal, f),
            Self::Unauthenticated => f.write_str("the frame's tag is not the bound guest's"),
            Self::StaleGeneration { frame, bound } => write!(
                f,
                "the frame is bound to boot generation {frame}, the link to {bound}"
            ),
            Self::StaleConnection { frame, bound } => {
                write!(f, "the frame is bound to {frame}, the link to {bound}")
            }
            Self::Sequence(refusal) => fmt::Display::fmt(refusal, f),
            Self::LinkAlreadyClosed => f.write_str("the link is closed"),
            Self::UnknownOperation { channel, code } => {
                write!(f, "operation {code:#04x} is unknown on the {channel} channel")
            }
            Self::WrongDirection { channel, operation } => write!(
                f,
                "the guest may not send {operation} on the {channel} channel"
            ),
            Self::ChannelClosed { channel } => write!(f, "the {channel} channel is closed"),
            Self::MessageTooLarge {
                channel,
                payload_bytes,
                max_message_bytes,
            } => write!(
                f,
                "a {payload_bytes}-byte message exceeds the {max_message_bytes} bytes of the {channel} channel"
            ),
            Self::HandshakeIncomplete { operation } => {
                write!(f, "{operation} arrived before the guest's hello")
            }
            Self::HandshakeRepeated => f.write_str("a second hello arrived"),
            Self::UnsupportedGuestVersion { version } => write!(
                f,
                "the guest speaks protocol version {version}, the host {PROTOCOL_VERSION}"
            ),
            Self::ClaimedIdentityDisagrees { field } => write!(
                f,
                "the guest's claimed {} is not the one the host bound",
                match field {
                    ClaimedField::Vm => "VM",
                    ClaimedField::Boot => "boot generation",
                }
            ),
            Self::Payload(refusal) => fmt::Display::fmt(refusal, f),
            Self::StreamParity { stream } => {
                write!(f, "stream {stream} has host parity; guest streams are odd")
            }
            Self::StreamIdNotIncreasing { stream, highest } => write!(
                f,
                "stream {stream} is not above the highest guest stream {highest}"
            ),
            Self::StreamQuotaExceeded {
                channel,
                max_streams,
            } => write!(f, "the {channel} channel already has {max_streams} streams"),
            Self::StreamNotOpen { channel, stream } => {
                write!(f, "{channel} stream {stream} is not open")
            }
            Self::StreamNotOpening { channel, stream } => {
                write!(f, "{channel} stream {stream} is not awaiting the guest's answer")
            }
            Self::StreamCancelled { channel, stream } => {
                write!(f, "{channel} stream {stream} was cancelled")
            }
            Self::HalfClosed { channel, stream } => {
                write!(f, "the guest already ended {channel} stream {stream}")
            }
            Self::WindowExceeded {
                channel,
                remaining_bytes,
                needed_bytes,
            } => write!(
                f,
                "{needed_bytes} bytes exceed the {remaining_bytes} bytes of {channel} window left"
            ),
            Self::StreamWindowExceeded {
                channel,
                stream,
                remaining_bytes,
                needed_bytes,
            } => write!(
                f,
                "{needed_bytes} bytes exceed the {remaining_bytes} bytes of {channel} stream {stream}'s window left"
            ),
        }
    }
}

impl std::error::Error for RefusalReason {}

/// What a refusal did beyond dropping the frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "effect", rename_all = "snake_case")]
pub enum RefusalEffect {
    FrameDropped,
    ChannelClosed { channel: Channel },
    LinkClosed,
}

/// A refused frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Refusal {
    pub reason: RefusalReason,
    pub effect: RefusalEffect,
}

/// Why a channel closed while the link stayed up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "channel_close", rename_all = "snake_case")]
pub enum ChannelCloseCause {
    WindowExceeded {
        remaining_bytes: u64,
        needed_bytes: u64,
    },
    /// An ingress or egress stream's window was exceeded.
    StreamWindowExceeded {
        stream: StreamId,
        remaining_bytes: u64,
        needed_bytes: u64,
    },
}

/// Why the link closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "close", rename_all = "snake_case")]
pub enum CloseCause {
    Violation(RefusalReason),
    GuestClosed {
        reason: CloseReason,
    },
    HostClosed {
        reason: CloseReason,
    },
    HandshakeTimedOut,
    IdleTimedOut,
    /// A frame stayed incomplete longer than the completion timeout (a slow peer).
    FrameTimedOut,
    PeerDisconnected,
    RefusalBudgetExhausted {
        max_refusals: u32,
    },
    /// The host-to-guest sequence is used up: no frame, not even a close, can be sealed
    /// on this connection any more. A new connection starts again at 1.
    SequenceExhausted,
}

impl CloseCause {
    /// The reason the final close frame carries.
    pub const fn close_reason(&self) -> CloseReason {
        match self {
            Self::Violation(_) | Self::RefusalBudgetExhausted { .. } => {
                CloseReason::ProtocolViolation
            }
            Self::GuestClosed { .. } | Self::PeerDisconnected | Self::SequenceExhausted => {
                CloseReason::Orderly
            }
            Self::HostClosed { reason } => *reason,
            Self::HandshakeTimedOut | Self::IdleTimedOut | Self::FrameTimedOut => {
                CloseReason::TimedOut
            }
        }
    }
}

impl fmt::Display for CloseCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Violation(reason) => write!(f, "protocol violation: {reason}"),
            Self::GuestClosed { reason } => write!(f, "the guest closed the link ({reason:?})"),
            Self::HostClosed { reason } => write!(f, "the host closed the link ({reason:?})"),
            Self::HandshakeTimedOut => f.write_str("the guest's hello did not arrive in time"),
            Self::IdleTimedOut => f.write_str("the link stayed idle too long"),
            Self::FrameTimedOut => f.write_str("a frame stayed incomplete too long"),
            Self::PeerDisconnected => f.write_str("the peer disconnected"),
            Self::RefusalBudgetExhausted { max_refusals } => {
                write!(f, "{max_refusals} frames were refused")
            }
            Self::SequenceExhausted => {
                f.write_str("the host-to-guest sequence space of this connection is used up")
            }
        }
    }
}

/// The link's phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum LinkPhase {
    AwaitingHello,
    Open,
    Closed(CloseCause),
}

/// What receiving bytes, a tick or a disconnect produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum LinkEvent {
    /// A typed request for a later broker to authorize.
    Request(GuestRequest),
    /// A guest report; the guest's word, never a host fact.
    Report(GuestReport),
    Refused(Refusal),
    Closed(CloseCause),
    ChannelClosed {
        channel: Channel,
        cause: ChannelCloseCause,
    },
    /// A stream stayed half-opened past the open timeout and was dropped; `cancel_sent`
    /// says whether a cancel frame could be queued for the guest.
    StreamTimedOut {
        channel: Channel,
        stream: StreamId,
        cancel_sent: bool,
    },
}

/// Why the host could not send a message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "send_refusal", rename_all = "snake_case")]
pub enum SendRefusal {
    LinkClosed,
    /// Only revocation, shutdown and close may go out before the guest's hello.
    HandshakeIncomplete,
    /// The operation does not travel host-to-guest on that channel.
    WrongChannel {
        channel: Channel,
        operation: Operation,
    },
    ChannelClosed {
        channel: Channel,
    },
    Encode(EncodeRefusal),
    MessageTooLarge {
        channel: Channel,
        payload_bytes: usize,
        max_message_bytes: u32,
    },
    QueueFull {
        channel: Channel,
        max_queued_frames: u32,
    },
    StreamParity {
        stream: StreamId,
    },
    StreamIdNotIncreasing {
        stream: StreamId,
        highest: u32,
    },
    StreamQuotaExceeded {
        channel: Channel,
        max_streams: u32,
    },
    StreamNotOpen {
        channel: Channel,
        stream: StreamId,
    },
    StreamNotOpening {
        channel: Channel,
        stream: StreamId,
    },
    HalfClosed {
        channel: Channel,
        stream: StreamId,
    },
    /// The guest has not granted enough credit on the channel (backpressure).
    NoCredit {
        channel: Channel,
        available_bytes: u64,
        needed_bytes: u64,
    },
    /// The guest has not granted enough credit on the ingress or egress stream.
    NoStreamCredit {
        channel: Channel,
        stream: StreamId,
        available_bytes: u64,
        needed_bytes: u64,
    },
}

impl fmt::Display for SendRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinkClosed => f.write_str("the link is closed"),
            Self::HandshakeIncomplete => {
                f.write_str("the guest has not said hello; only control may be sent")
            }
            Self::WrongChannel { channel, operation } => {
                write!(f, "the host may not send {operation} on the {channel} channel")
            }
            Self::ChannelClosed { channel } => write!(f, "the {channel} channel is closed"),
            Self::Encode(refusal) => fmt::Display::fmt(refusal, f),
            Self::MessageTooLarge {
                channel,
                payload_bytes,
                max_message_bytes,
            } => write!(
                f,
                "a {payload_bytes}-byte message exceeds the {max_message_bytes} bytes of the {channel} channel"
            ),
            Self::QueueFull {
                channel,
                max_queued_frames,
            } => write!(
                f,
                "the {channel} channel already has {max_queued_frames} frames queued"
            ),
            Self::StreamParity { stream } => {
                write!(f, "stream {stream} has guest parity; host streams are even")
            }
            Self::StreamIdNotIncreasing { stream, highest } => write!(
                f,
                "stream {stream} is not above the highest host stream {highest}"
            ),
            Self::StreamQuotaExceeded {
                channel,
                max_streams,
            } => write!(f, "the {channel} channel already has {max_streams} streams"),
            Self::StreamNotOpen { channel, stream } => {
                write!(f, "{channel} stream {stream} is not open")
            }
            Self::StreamNotOpening { channel, stream } => {
                write!(f, "{channel} stream {stream} is not awaiting the host's answer")
            }
            Self::HalfClosed { channel, stream } => {
                write!(f, "the host already ended {channel} stream {stream}")
            }
            Self::NoCredit {
                channel,
                available_bytes,
                needed_bytes,
            } => write!(
                f,
                "{needed_bytes} bytes exceed the {available_bytes} bytes of {channel} credit the guest granted"
            ),
            Self::NoStreamCredit {
                channel,
                stream,
                available_bytes,
                needed_bytes,
            } => write!(
                f,
                "{needed_bytes} bytes exceed the {available_bytes} bytes of credit the guest granted {channel} stream {stream}"
            ),
        }
    }
}

impl std::error::Error for SendRefusal {}

/// Why consumed bytes could not be credited back to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "consume_refusal", rename_all = "snake_case")]
pub enum ConsumeRefusal {
    LinkClosed,
    NotBulk {
        channel: Channel,
    },
    ChannelClosed {
        channel: Channel,
    },
    MoreThanBuffered {
        channel: Channel,
        buffered_bytes: u64,
        consumed_bytes: u32,
    },
    QueueFull {
        channel: Channel,
        max_queued_frames: u32,
    },
    /// The channel is credited per stream ([`HostLink::consume_stream`]).
    PerStream {
        channel: Channel,
    },
    /// The channel is credited as a whole ([`HostLink::consume`]).
    NotPerStream {
        channel: Channel,
    },
    StreamMoreThanBuffered {
        channel: Channel,
        stream: StreamId,
        buffered_bytes: u64,
        consumed_bytes: u32,
    },
}

impl fmt::Display for ConsumeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinkClosed => f.write_str("the link is closed"),
            Self::NotBulk { channel } => write!(f, "the {channel} channel buffers nothing"),
            Self::ChannelClosed { channel } => write!(f, "the {channel} channel is closed"),
            Self::MoreThanBuffered {
                channel,
                buffered_bytes,
                consumed_bytes,
            } => write!(
                f,
                "{consumed_bytes} bytes consumed but only {buffered_bytes} are buffered on {channel}"
            ),
            Self::QueueFull {
                channel,
                max_queued_frames,
            } => write!(
                f,
                "the {channel} channel already has {max_queued_frames} frames queued; the credit was not applied"
            ),
            Self::PerStream { channel } => {
                write!(f, "the {channel} channel is credited per stream")
            }
            Self::NotPerStream { channel } => {
                write!(f, "the {channel} channel is credited as a whole")
            }
            Self::StreamMoreThanBuffered {
                channel,
                stream,
                buffered_bytes,
                consumed_bytes,
            } => write!(
                f,
                "{consumed_bytes} bytes consumed but only {buffered_bytes} are buffered on {channel} stream {stream}"
            ),
        }
    }
}

impl std::error::Error for ConsumeRefusal {}

/// A view of one channel's state. On the ingress and egress channels the byte counts are
/// the sums over the channel's streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ChannelSummary {
    pub channel: Channel,
    pub streams: usize,
    pub buffered_bytes: u64,
    pub receive_window_bytes: u64,
    pub send_credit_bytes: u64,
    pub queued_frames: usize,
    pub closed: Option<ChannelCloseCause>,
}

struct QueuedFrame {
    channel: Channel,
    operation: Operation,
    stream: u32,
    payload: Vec<u8>,
    /// The guest's credit this frame was charged when it was queued (its data bytes);
    /// returned if the frame is dropped unsent.
    credit_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct StreamState {
    opener: Sender,
    open: bool,
    guest_ended: bool,
    host_ended: bool,
    since: MonotonicTime,
    /// Ingress and egress (module docs): what the host may still send on the stream.
    send_window_bytes: u64,
    /// What the guest may still send on the stream before the host credits more.
    receive_window_bytes: u64,
    /// The guest's bytes received and not consumed yet.
    buffered_bytes: u64,
    /// What the host keeps the guest's window plus its buffered bytes at.
    window_bytes: u64,
    /// The guest's bytes consumed since the open.
    consumed_bytes: u64,
}

impl StreamState {
    fn new(opener: Sender, since: MonotonicTime) -> Self {
        Self {
            opener,
            open: false,
            guest_ended: false,
            host_ended: false,
            since,
            send_window_bytes: STREAM_WINDOW_BYTES,
            receive_window_bytes: STREAM_WINDOW_BYTES,
            buffered_bytes: 0,
            window_bytes: STREAM_WINDOW_BYTES,
            consumed_bytes: 0,
        }
    }
}

struct ChannelState {
    channel: Channel,
    quota: ChannelQuota,
    streams: BTreeMap<u32, StreamState>,
    highest_guest_stream: u32,
    highest_host_stream: u32,
    receive_window_bytes: u64,
    buffered_bytes: u64,
    send_credit_bytes: u64,
    queue: VecDeque<QueuedFrame>,
    closed: Option<ChannelCloseCause>,
    cancelled: VecDeque<u32>,
    /// Receive window taken by guest data the host dropped (data for a cancelled stream)
    /// and not yet credited back, because the queue had no room for the window update.
    held_credit_bytes: u64,
    /// Ingress and egress: how far the streams' windows grew past their first windows, in
    /// all; at most the quota's buffered-byte count.
    grown_bytes: u64,
    /// Streams both ends finished, so credit that crossed the finish is dropped quietly;
    /// bounded by the stream quota.
    ended: VecDeque<u32>,
    /// Streams whose credit found the queue full; retried as frames go out.
    grants_due: BTreeSet<u32>,
}

impl ChannelState {
    fn new(channel: Channel, quota: ChannelQuota) -> Self {
        Self {
            channel,
            quota,
            streams: BTreeMap::new(),
            highest_guest_stream: 0,
            highest_host_stream: 0,
            receive_window_bytes: quota.max_buffered_bytes,
            buffered_bytes: 0,
            send_credit_bytes: 0,
            queue: VecDeque::new(),
            closed: None,
            cancelled: VecDeque::new(),
            held_credit_bytes: 0,
            grown_bytes: 0,
            ended: VecDeque::new(),
            grants_due: BTreeSet::new(),
        }
    }

    fn summary(&self) -> ChannelSummary {
        let (buffered_bytes, receive_window_bytes, send_credit_bytes) =
            if self.channel.has_stream_windows() {
                self.streams.values().fold(
                    (0u64, 0u64, 0u64),
                    |(buffered, receive, send), stream| {
                        (
                            buffered.saturating_add(stream.buffered_bytes),
                            receive.saturating_add(stream.receive_window_bytes),
                            send.saturating_add(stream.send_window_bytes),
                        )
                    },
                )
            } else {
                (
                    self.buffered_bytes,
                    self.receive_window_bytes,
                    self.send_credit_bytes,
                )
            };
        ChannelSummary {
            channel: self.channel,
            streams: self.streams.len(),
            buffered_bytes,
            receive_window_bytes,
            send_credit_bytes,
            queued_frames: self.queue.len(),
            closed: self.closed,
        }
    }

    fn was_cancelled(&self, stream: u32) -> bool {
        self.cancelled.contains(&stream)
    }

    fn was_ended(&self, stream: u32) -> bool {
        self.ended.contains(&stream)
    }

    /// Drops a stream; what its window grew goes back to the channel.
    fn remove_stream(&mut self, stream: u32) -> Option<StreamState> {
        let removed = self.streams.remove(&stream)?;
        self.grown_bytes = self
            .grown_bytes
            .saturating_sub(removed.window_bytes.saturating_sub(STREAM_WINDOW_BYTES));
        self.grants_due.remove(&stream);
        Some(removed)
    }

    /// Drops a stream both ends finished (or whose open was refused) and remembers it as
    /// ended, in a set bounded by the stream quota.
    fn complete(&mut self, stream: u32) {
        self.remove_stream(stream);
        self.ended.push_back(stream);
        while self.ended.len() > self.quota.max_streams.max(1) as usize {
            self.ended.pop_front();
        }
    }

    /// Forgets a stream: drops its queued frames, returns the guest's credit their data
    /// was charged (the guest never receives it, so it never credits it back), and
    /// remembers the stream as cancelled, in a set bounded by the stream quota.
    fn forget(&mut self, stream: u32) {
        self.remove_stream(stream);
        let mut returned = 0u64;
        self.queue.retain(|frame| {
            let keep = frame.stream != stream;
            if !keep {
                returned = returned.saturating_add(frame.credit_bytes);
            }
            keep
        });
        self.send_credit_bytes = self.send_credit_bytes.saturating_add(returned);
        self.cancelled.push_back(stream);
        while self.cancelled.len() > self.quota.max_streams.max(1) as usize {
            self.cancelled.pop_front();
        }
    }

    fn clear(&mut self) {
        self.streams.clear();
        self.queue.clear();
        self.grown_bytes = 0;
        self.grants_due.clear();
    }
}

/// Seals a frame: header bytes, payload and the sender's tag over both.
pub fn seal(
    binding: &LinkBinding,
    sender: Sender,
    header: &FrameHeader,
    payload: &[u8],
) -> Vec<u8> {
    let header_bytes = header.encode();
    let tag = binding.tag(sender, &header_bytes, payload);
    let mut bytes = Vec::with_capacity(header_bytes.len() + payload.len() + tag.len());
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&tag);
    bytes
}

/// Encodes a whole frame for `message` from `sender` with `sequence`, bound to the
/// binding's boot generation and to [`Connection::UNCHALLENGED`], as the test-only
/// `HostLink::new` expects.
pub fn encode_frame(
    binding: &LinkBinding,
    sender: Sender,
    sequence: u64,
    message: &LinkMessage,
) -> Result<Vec<u8>, EncodeRefusal> {
    encode_frame_on(binding, Connection::UNCHALLENGED, sender, sequence, message)
}

/// Encodes a whole frame for `message` from `sender` with `sequence`, bound to the
/// binding's boot generation and to `connection`: the nonce of the host's challenge on
/// a link made with [`HostLink::connect`]. Both ends produce frames this way.
pub fn encode_frame_on(
    binding: &LinkBinding,
    connection: Connection,
    sender: Sender,
    sequence: u64,
    message: &LinkMessage,
) -> Result<Vec<u8>, EncodeRefusal> {
    let payload = message.encode_payload()?;
    let header = FrameHeader {
        channel: message.channel(),
        operation_code: message.operation().code(),
        stream: message.stream_code(),
        sequence,
        boot_generation: binding.boot().get(),
        payload_bytes: u32::try_from(payload.len()).unwrap_or(u32::MAX),
        connection,
    };
    Ok(seal(binding, sender, &header, &payload))
}

/// The host end of one guest link: one connection of one boot.
pub struct HostLink<C: Clock> {
    binding: LinkBinding,
    connection: Connection,
    limits: LinkLimits,
    clock: C,
    decoder: FrameDecoder,
    inbound: SequenceState,
    outbound: SequenceState,
    phase: LinkPhase,
    /// When the handshake timeout started: at creation for a link with no challenge, and
    /// when the challenge was sealed for the transport for a challenged link, so a slow
    /// start of the transport does not eat the guest's time to answer.
    handshake_since: Option<MonotonicTime>,
    last_received_at: MonotonicTime,
    refusals: u32,
    channels: Vec<ChannelState>,
    urgent: VecDeque<QueuedFrame>,
    next_bulk: usize,
    /// A close no call has returned as an event yet (an exhausted sequence).
    unreported: Option<CloseCause>,
}

impl<C: Clock> HostLink<C> {
    /// A link bound to `binding` and to no connection, under `limits`, started now on
    /// `clock`; the limits are validated first. It sends no challenge and takes the
    /// guest's hello as its first frame, with every frame on
    /// [`Connection::UNCHALLENGED`], so frames recorded on an earlier unchallenged link
    /// of the same boot are accepted on this one. [`HostLink::connect`] binds the
    /// connection. It exists only in test builds, for the in-process rigs that still drive
    /// a link without a connection: `sandbox/probes/fakes.rs`, `sandbox/guest_files/fakes.rs`
    /// and `sandbox/guest_files/tests.rs` in the tree, and this module's and
    /// `link_transport`'s own tests. Every other link is made with [`HostLink::connect`]
    /// (the sandbox host and `LinkDriver::connect` do), and a guest of protocol version 2
    /// waits for the challenge before its hello.
    #[cfg(test)]
    pub(crate) fn new(
        binding: LinkBinding,
        limits: LinkLimits,
        clock: C,
    ) -> Result<Self, LimitsError> {
        Self::bound(binding, Connection::UNCHALLENGED, limits, clock)
    }

    /// A link for one new connection: bound to `binding` and to `nonce`, which the host
    /// drew for this connection alone, under `limits`, started now on `clock`; the limits
    /// are validated first. Its first outbound frame is the challenge carrying the nonce;
    /// the guest's hello and every later frame must carry it too. Frames, acknowledgments
    /// and tags of any earlier connection of the same boot are refused, and both
    /// sequences start at 1.
    pub fn connect(
        binding: LinkBinding,
        nonce: ConnectionNonce,
        limits: LinkLimits,
        clock: C,
    ) -> Result<Self, LimitsError> {
        let connection = nonce.connection();
        let mut link = Self::bound(binding, connection, limits, clock)?;
        // The challenge is urgent; the urgent queue has no budget for the link's own
        // frames and a 16-byte field always encodes, so this cannot fail.
        let _ = link.enqueue_internal(LinkMessage::Challenge { connection });
        Ok(link)
    }

    fn bound(
        binding: LinkBinding,
        connection: Connection,
        limits: LinkLimits,
        clock: C,
    ) -> Result<Self, LimitsError> {
        limits.validate()?;
        let now = clock.now();
        let channels = Channel::ALL
            .iter()
            .map(|channel| ChannelState::new(*channel, *limits.quota(*channel)))
            .collect();
        Ok(Self {
            binding,
            connection,
            decoder: FrameDecoder::new(limits.max_frame_bytes),
            limits,
            clock,
            inbound: SequenceState::new(),
            outbound: SequenceState::new(),
            phase: LinkPhase::AwaitingHello,
            handshake_since: connection.is_unchallenged().then_some(now),
            last_received_at: now,
            refusals: 0,
            channels,
            urgent: VecDeque::new(),
            next_bulk: 0,
            unreported: None,
        })
    }

    pub fn binding(&self) -> &LinkBinding {
        &self.binding
    }

    /// The connection every frame of this link carries; [`Connection::UNCHALLENGED`]
    /// for a link made with the test-only `HostLink::new`.
    pub fn connection(&self) -> Connection {
        self.connection
    }

    pub fn limits(&self) -> &LinkLimits {
        &self.limits
    }

    pub fn phase(&self) -> &LinkPhase {
        &self.phase
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.phase, LinkPhase::Closed(_))
    }

    /// Frames refused and charged to the budget so far.
    pub fn refusals(&self) -> u32 {
        self.refusals
    }

    pub fn channel(&self, channel: Channel) -> ChannelSummary {
        self.state(channel).summary()
    }

    /// Bytes the decoder holds for an incomplete frame.
    pub fn decoder_buffered_bytes(&self) -> usize {
        self.decoder.buffered_bytes()
    }

    /// Frames waiting to go out, urgent ones included.
    pub fn queued_frames(&self) -> usize {
        self.urgent.len()
            + self
                .channels
                .iter()
                .map(|state| state.queue.len())
                .sum::<usize>()
    }

    /// The last guest-to-host sequence accepted.
    pub fn last_received_sequence(&self) -> u64 {
        self.inbound.last_accepted()
    }

    /// The last host-to-guest sequence sealed.
    pub fn last_sent_sequence(&self) -> u64 {
        self.outbound.last_accepted()
    }

    /// Events of closes that happened where no event could be returned: today only the
    /// close when [`HostLink::next_outbound`] finds the host-to-guest sequence used up
    /// ([`CloseCause::SequenceExhausted`]). Each is returned once: here, or at the start
    /// of the next [`HostLink::receive`], [`HostLink::peer_closed`] or
    /// [`HostLink::tick`].
    pub fn take_events(&mut self) -> Vec<LinkEvent> {
        self.unreported
            .take()
            .map(LinkEvent::Closed)
            .into_iter()
            .collect()
    }

    /// Sets the host-to-guest sequence as if `last` frames had been sent.
    #[cfg(test)]
    pub(crate) fn set_last_sent_sequence(&mut self, last: u64) {
        self.outbound = SequenceState::after(last);
    }

    fn state(&self, channel: Channel) -> &ChannelState {
        &self.channels[channel.index()]
    }

    fn state_mut(&mut self, channel: Channel) -> &mut ChannelState {
        &mut self.channels[channel.index()]
    }

    /// Feeds bytes from the guest. Returns the events in order; after the link closes,
    /// every later push yields one refusal.
    pub fn receive(&mut self, bytes: &[u8]) -> Vec<LinkEvent> {
        let mut events = self.take_events();
        if self.is_closed() {
            if !bytes.is_empty() {
                events.push(LinkEvent::Refused(Refusal {
                    reason: RefusalReason::LinkAlreadyClosed,
                    effect: RefusalEffect::FrameDropped,
                }));
            }
            return events;
        }
        let now = self.clock.now();
        for step in self.decoder.push(bytes, now) {
            match step {
                DecodeStep::Refused(refusal) => {
                    self.violation(RefusalReason::Framing(refusal), &mut events);
                    break;
                }
                DecodeStep::Frame(raw) => {
                    self.accept_frame(raw, now, &mut events);
                    if self.is_closed() {
                        break;
                    }
                }
            }
        }
        events
    }

    /// The transport reported the peer gone. A partial frame is a truncation.
    pub fn peer_closed(&mut self) -> Vec<LinkEvent> {
        let mut events = self.take_events();
        if self.is_closed() {
            return events;
        }
        match self.decoder.finish() {
            Some(truncated) => self.violation(RefusalReason::Framing(truncated), &mut events),
            None => {
                self.close_link(CloseCause::PeerDisconnected);
                events.push(LinkEvent::Closed(CloseCause::PeerDisconnected));
            }
        }
        events
    }

    /// Applies the timeouts at the clock's current time: an incomplete frame past the
    /// completion timeout, a missing hello past the handshake timeout, silence past the
    /// idle timeout, and streams half-opened past the open timeout. A duration equal to
    /// the timeout is still within it.
    pub fn tick(&mut self) -> Vec<LinkEvent> {
        let mut events = self.take_events();
        if self.is_closed() {
            return events;
        }
        let now = self.clock.now();
        if let Some(since) = self.decoder.partial_since() {
            if now.saturating_duration_since(since) > self.limits.frame_completion_timeout {
                self.close_link(CloseCause::FrameTimedOut);
                events.push(LinkEvent::Closed(CloseCause::FrameTimedOut));
                return events;
            }
        }
        let timed_out = match self.phase {
            LinkPhase::AwaitingHello => self
                .handshake_since
                .is_some_and(|since| {
                    now.saturating_duration_since(since) > self.limits.handshake_timeout
                })
                .then_some(CloseCause::HandshakeTimedOut),
            LinkPhase::Open => (now.saturating_duration_since(self.last_received_at)
                > self.limits.idle_timeout)
                .then_some(CloseCause::IdleTimedOut),
            LinkPhase::Closed(_) => None,
        };
        if let Some(cause) = timed_out {
            self.close_link(cause.clone());
            events.push(LinkEvent::Closed(cause));
            return events;
        }
        let open_timeout = self.limits.open_timeout;
        for channel in Channel::BULK {
            let expired: Vec<u32> = self
                .state(channel)
                .streams
                .iter()
                .filter(|(_, stream)| {
                    !stream.open && now.saturating_duration_since(stream.since) > open_timeout
                })
                .map(|(id, _)| *id)
                .collect();
            for id in expired {
                let Some(stream) = StreamId::new(id) else {
                    continue;
                };
                self.state_mut(channel).forget(id);
                let cancel_sent = self
                    .enqueue_internal(LinkMessage::Cancel {
                        channel,
                        stream,
                        cause: CancelCause::TimedOut,
                    })
                    .is_ok();
                events.push(LinkEvent::StreamTimedOut {
                    channel,
                    stream,
                    cancel_sent,
                });
            }
        }
        events
    }

    /// Queues a message for the guest after checking it against the direction table,
    /// the channel's quota, stream state and the guest's credit. Revocation, shutdown and
    /// close go to the urgent queue, which drains before everything else; a close also
    /// closes the link.
    pub fn send(&mut self, message: HostMessage) -> Result<(), SendRefusal> {
        if self.is_closed() {
            return Err(SendRefusal::LinkClosed);
        }
        let message: LinkMessage = message.into();
        let channel = message.channel();
        let operation = message.operation();
        if !operation
            .direction(channel)
            .is_some_and(|direction| direction.allows(Sender::Host))
        {
            return Err(SendRefusal::WrongChannel { channel, operation });
        }
        if matches!(self.phase, LinkPhase::AwaitingHello) && !operation.is_urgent() {
            return Err(SendRefusal::HandshakeIncomplete);
        }
        if self.state(channel).closed.is_some() {
            return Err(SendRefusal::ChannelClosed { channel });
        }
        let payload = message.encode_payload().map_err(SendRefusal::Encode)?;
        let quota = *self.limits.quota(channel);
        if payload.len() > quota.max_message_bytes as usize {
            return Err(SendRefusal::MessageTooLarge {
                channel,
                payload_bytes: payload.len(),
                max_message_bytes: quota.max_message_bytes,
            });
        }
        let queue_len = if operation.is_urgent() {
            self.urgent.len()
        } else {
            self.state(channel).queue.len()
        };
        if queue_len >= quota.max_queued_frames as usize {
            return Err(SendRefusal::QueueFull {
                channel,
                max_queued_frames: quota.max_queued_frames,
            });
        }
        if let LinkMessage::Close { reason } = message {
            self.close_link(CloseCause::HostClosed { reason });
            return Ok(());
        }
        let now = self.clock.now();
        self.apply_host_stream_rules(&message, now)?;
        let credit_bytes = match &message {
            LinkMessage::Data { channel, bytes, .. } if !channel.has_stream_windows() => {
                bytes.len() as u64
            }
            _ => 0,
        };
        let frame = QueuedFrame {
            channel,
            operation,
            stream: message.stream_code(),
            payload,
            credit_bytes,
        };
        if operation.is_urgent() {
            self.urgent.push_back(frame);
        } else {
            self.state_mut(channel).queue.push_back(frame);
        }
        Ok(())
    }

    fn apply_host_stream_rules(
        &mut self,
        message: &LinkMessage,
        now: MonotonicTime,
    ) -> Result<(), SendRefusal> {
        match message {
            LinkMessage::Open { stream, open } => {
                let channel = open.channel();
                if stream.opener() != Sender::Host {
                    return Err(SendRefusal::StreamParity { stream: *stream });
                }
                let state = self.state_mut(channel);
                if stream.get() <= state.highest_host_stream {
                    return Err(SendRefusal::StreamIdNotIncreasing {
                        stream: *stream,
                        highest: state.highest_host_stream,
                    });
                }
                if state.streams.len() >= state.quota.max_streams as usize {
                    return Err(SendRefusal::StreamQuotaExceeded {
                        channel,
                        max_streams: state.quota.max_streams,
                    });
                }
                state.highest_host_stream = stream.get();
                state
                    .streams
                    .insert(stream.get(), StreamState::new(Sender::Host, now));
            }
            LinkMessage::Opened { channel, stream }
            | LinkMessage::OpenRefused {
                channel, stream, ..
            } => {
                let opened = matches!(message, LinkMessage::Opened { .. });
                let state = self.state_mut(*channel);
                match state.streams.get(&stream.get()) {
                    Some(entry) if entry.opener == Sender::Guest && !entry.open => {}
                    Some(_) => {
                        return Err(SendRefusal::StreamNotOpening {
                            channel: *channel,
                            stream: *stream,
                        })
                    }
                    None => {
                        return Err(SendRefusal::StreamNotOpen {
                            channel: *channel,
                            stream: *stream,
                        })
                    }
                }
                if opened {
                    if let Some(entry) = state.streams.get_mut(&stream.get()) {
                        entry.open = true;
                    }
                } else {
                    state.complete(stream.get());
                }
            }
            LinkMessage::Data {
                channel,
                stream,
                bytes,
            } => {
                let state = self.state_mut(*channel);
                let entry = state
                    .streams
                    .get_mut(&stream.get())
                    .filter(|entry| entry.open)
                    .ok_or(SendRefusal::StreamNotOpen {
                        channel: *channel,
                        stream: *stream,
                    })?;
                if entry.host_ended {
                    return Err(SendRefusal::HalfClosed {
                        channel: *channel,
                        stream: *stream,
                    });
                }
                let needed_bytes = bytes.len() as u64;
                if channel.has_stream_windows() {
                    if needed_bytes > entry.send_window_bytes {
                        return Err(SendRefusal::NoStreamCredit {
                            channel: *channel,
                            stream: *stream,
                            available_bytes: entry.send_window_bytes,
                            needed_bytes,
                        });
                    }
                    entry.send_window_bytes -= needed_bytes;
                    return Ok(());
                }
                if needed_bytes > state.send_credit_bytes {
                    return Err(SendRefusal::NoCredit {
                        channel: *channel,
                        available_bytes: state.send_credit_bytes,
                        needed_bytes,
                    });
                }
                state.send_credit_bytes -= needed_bytes;
            }
            LinkMessage::EndOfStream { channel, stream } => {
                let state = self.state_mut(*channel);
                let entry = state
                    .streams
                    .get(&stream.get())
                    .filter(|entry| entry.open)
                    .copied()
                    .ok_or(SendRefusal::StreamNotOpen {
                        channel: *channel,
                        stream: *stream,
                    })?;
                if entry.host_ended {
                    return Err(SendRefusal::HalfClosed {
                        channel: *channel,
                        stream: *stream,
                    });
                }
                if entry.guest_ended {
                    state.complete(stream.get());
                } else if let Some(entry) = state.streams.get_mut(&stream.get()) {
                    entry.host_ended = true;
                }
            }
            LinkMessage::Cancel {
                channel, stream, ..
            } => {
                let state = self.state_mut(*channel);
                if !state.streams.contains_key(&stream.get()) {
                    return Err(SendRefusal::StreamNotOpen {
                        channel: *channel,
                        stream: *stream,
                    });
                }
                state.forget(stream.get());
            }
            LinkMessage::Resize { stream, .. } => {
                let state = self.state(Channel::Terminal);
                if !state
                    .streams
                    .get(&stream.get())
                    .is_some_and(|entry| entry.open)
                {
                    return Err(SendRefusal::StreamNotOpen {
                        channel: Channel::Terminal,
                        stream: *stream,
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Queues a frame the link itself issues (welcome, close, window updates, timeout
    /// cancels); urgent operations bypass the host-sent budget of the urgent queue.
    fn enqueue_internal(&mut self, message: LinkMessage) -> Result<(), SendRefusal> {
        let channel = message.channel();
        let operation = message.operation();
        let payload = message.encode_payload().map_err(SendRefusal::Encode)?;
        let frame = QueuedFrame {
            channel,
            operation,
            stream: message.stream_code(),
            payload,
            credit_bytes: 0,
        };
        if operation.is_urgent() {
            self.urgent.push_back(frame);
            return Ok(());
        }
        let state = self.state_mut(channel);
        if state.queue.len() >= state.quota.max_queued_frames as usize {
            return Err(SendRefusal::QueueFull {
                channel,
                max_queued_frames: state.quota.max_queued_frames,
            });
        }
        if matches!(
            operation,
            Operation::WindowUpdate | Operation::StreamWindowUpdate
        ) {
            state.queue.push_front(frame);
        } else {
            state.queue.push_back(frame);
        }
        Ok(())
    }

    /// The next frame to write to the transport, sealed with the next host-to-guest
    /// sequence: the urgent queue first, then control, then the bulk channels in turn.
    /// When the sequence is used up the frame is dropped and the link closes with
    /// [`CloseCause::SequenceExhausted`] and no close frame; that close is returned once
    /// as an event by [`HostLink::take_events`] or the next call that returns events.
    pub fn next_outbound(&mut self) -> Option<Vec<u8>> {
        let frame = self.dequeue()?;
        let sequence = match self.outbound.next_for_send() {
            Ok(sequence) => sequence,
            Err(_) => {
                if !self.is_closed() {
                    self.phase = LinkPhase::Closed(CloseCause::SequenceExhausted);
                    self.unreported = Some(CloseCause::SequenceExhausted);
                    self.decoder.close(FramingRefusal::DecoderClosed);
                    self.urgent.clear();
                    for state in &mut self.channels {
                        state.clear();
                    }
                }
                return None;
            }
        };
        let header = FrameHeader {
            channel: frame.channel,
            operation_code: frame.operation.code(),
            stream: frame.stream,
            sequence,
            boot_generation: self.binding.boot().get(),
            payload_bytes: u32::try_from(frame.payload.len()).unwrap_or(u32::MAX),
            connection: self.connection,
        };
        if self.handshake_since.is_none() {
            // The challenge goes to the transport now: the guest's time to answer starts.
            self.handshake_since = Some(self.clock.now());
        }
        // Taking a frame made room: credit held back for dropped guest data goes out, and
        // streams' credit that found the queue full.
        for channel in Channel::BULK {
            self.return_held_credit(channel);
            if !self.state(channel).grants_due.is_empty() {
                let due: Vec<u32> = self.state(channel).grants_due.iter().copied().collect();
                for stream in due {
                    self.grant_stream(channel, stream);
                }
            }
        }
        Some(seal(&self.binding, Sender::Host, &header, &frame.payload))
    }

    /// Credits the receive window held for dropped guest data back to the guest with one
    /// window update, if the channel's queue has room; otherwise it stays held.
    fn return_held_credit(&mut self, channel: Channel) {
        let state = self.state(channel);
        if state.held_credit_bytes == 0 || state.closed.is_some() || self.is_closed() {
            return;
        }
        let credit_bytes = u32::try_from(state.held_credit_bytes).unwrap_or(u32::MAX);
        if self
            .enqueue_internal(LinkMessage::WindowUpdate {
                channel,
                credit_bytes,
            })
            .is_ok()
        {
            let state = self.state_mut(channel);
            state.held_credit_bytes -= u64::from(credit_bytes);
            state.receive_window_bytes += u64::from(credit_bytes);
        }
    }

    fn dequeue(&mut self) -> Option<QueuedFrame> {
        if let Some(frame) = self.urgent.pop_front() {
            return Some(frame);
        }
        if let Some(frame) = self.state_mut(Channel::Control).queue.pop_front() {
            return Some(frame);
        }
        for offset in 0..Channel::BULK.len() {
            let index = (self.next_bulk + offset) % Channel::BULK.len();
            if let Some(frame) = self.state_mut(Channel::BULK[index]).queue.pop_front() {
                self.next_bulk = (index + 1) % Channel::BULK.len();
                return Some(frame);
            }
        }
        None
    }

    /// The host consumed `bytes` of what it buffered on `channel`: the receive window
    /// grows back and a window update is queued ahead of that channel's data.
    pub fn consume(&mut self, channel: Channel, bytes: u32) -> Result<(), ConsumeRefusal> {
        if self.is_closed() {
            return Err(ConsumeRefusal::LinkClosed);
        }
        if !channel.is_bulk() {
            return Err(ConsumeRefusal::NotBulk { channel });
        }
        if channel.has_stream_windows() {
            return Err(ConsumeRefusal::PerStream { channel });
        }
        let state = self.state(channel);
        if state.closed.is_some() {
            return Err(ConsumeRefusal::ChannelClosed { channel });
        }
        if u64::from(bytes) > state.buffered_bytes {
            return Err(ConsumeRefusal::MoreThanBuffered {
                channel,
                buffered_bytes: state.buffered_bytes,
                consumed_bytes: bytes,
            });
        }
        if state.queue.len() >= state.quota.max_queued_frames as usize {
            return Err(ConsumeRefusal::QueueFull {
                channel,
                max_queued_frames: state.quota.max_queued_frames,
            });
        }
        self.return_held_credit(channel);
        let state = self.state(channel);
        if state.queue.len() >= state.quota.max_queued_frames as usize {
            return Err(ConsumeRefusal::QueueFull {
                channel,
                max_queued_frames: state.quota.max_queued_frames,
            });
        }
        let state = self.state_mut(channel);
        state.buffered_bytes -= u64::from(bytes);
        state.receive_window_bytes += u64::from(bytes);
        self.enqueue_internal(LinkMessage::WindowUpdate {
            channel,
            credit_bytes: bytes,
        })
        .map_err(|_| ConsumeRefusal::QueueFull {
            channel,
            max_queued_frames: self.state(channel).quota.max_queued_frames,
        })
    }

    /// The host consumed `bytes` the guest sent on ingress or egress `stream`: the stream is
    /// credited back to its window (module docs: its first window, or grown once it consumed
    /// a whole first window and the channel's growth stays within its quota), in one update
    /// once a quarter of the window is due. Nothing is credited for a stream the guest ended
    /// its direction of, and bytes of a stream the link no longer holds need no credit.
    pub fn consume_stream(
        &mut self,
        channel: Channel,
        stream: StreamId,
        bytes: u32,
    ) -> Result<(), ConsumeRefusal> {
        if self.is_closed() {
            return Err(ConsumeRefusal::LinkClosed);
        }
        if !channel.has_stream_windows() {
            return Err(ConsumeRefusal::NotPerStream { channel });
        }
        let growth_quota = self.limits.quota(channel).max_buffered_bytes;
        let state = self.state_mut(channel);
        if state.closed.is_some() {
            return Err(ConsumeRefusal::ChannelClosed { channel });
        }
        let Some(entry) = state.streams.get_mut(&stream.get()) else {
            return Ok(());
        };
        if u64::from(bytes) > entry.buffered_bytes {
            return Err(ConsumeRefusal::StreamMoreThanBuffered {
                channel,
                stream,
                buffered_bytes: entry.buffered_bytes,
                consumed_bytes: bytes,
            });
        }
        entry.buffered_bytes -= u64::from(bytes);
        entry.consumed_bytes = entry.consumed_bytes.saturating_add(u64::from(bytes));
        if entry.window_bytes < MAX_STREAM_WINDOW_BYTES
            && entry.consumed_bytes >= STREAM_WINDOW_BYTES
        {
            let growth = MAX_STREAM_WINDOW_BYTES - entry.window_bytes;
            if state.grown_bytes.saturating_add(growth) <= growth_quota {
                entry.window_bytes = MAX_STREAM_WINDOW_BYTES;
                state.grown_bytes += growth;
            }
        }
        self.grant_stream(channel, stream.get());
        Ok(())
    }

    /// What the host may send on ingress or egress `stream` now: the guest's credit for it.
    /// Zero for a stream not open, or of another channel.
    pub fn stream_send_credit(&self, channel: Channel, stream: StreamId) -> u64 {
        if !channel.has_stream_windows() {
            return 0;
        }
        self.state(channel)
            .streams
            .get(&stream.get())
            .filter(|entry| entry.open)
            .map_or(0, |entry| entry.send_window_bytes)
    }

    /// Queues the credit due to `stream` (its window less what the guest may send and what
    /// the host holds) once it is a quarter of the window; a full queue leaves it due for
    /// the next frame.
    fn grant_stream(&mut self, channel: Channel, stream: u32) {
        let Some(entry) = self.state(channel).streams.get(&stream).copied() else {
            self.state_mut(channel).grants_due.remove(&stream);
            return;
        };
        let held = entry
            .receive_window_bytes
            .saturating_add(entry.buffered_bytes);
        let due = entry.window_bytes.saturating_sub(held);
        let Some(id) = StreamId::new(stream) else {
            return;
        };
        if entry.guest_ended || due == 0 || due < entry.window_bytes / 4 {
            self.state_mut(channel).grants_due.remove(&stream);
            return;
        }
        let credit_bytes = u32::try_from(due).unwrap_or(u32::MAX);
        let queued = self
            .enqueue_internal(LinkMessage::StreamWindowUpdate {
                channel,
                stream: id,
                credit_bytes,
            })
            .is_ok();
        let state = self.state_mut(channel);
        if queued {
            state.grants_due.remove(&stream);
            if let Some(entry) = state.streams.get_mut(&stream) {
                entry.receive_window_bytes += u64::from(credit_bytes);
            }
        } else {
            state.grants_due.insert(stream);
        }
    }

    fn accept_frame(&mut self, raw: RawFrame, now: MonotonicTime, events: &mut Vec<LinkEvent>) {
        let header = raw.header;
        if !self
            .binding
            .verify(Sender::Guest, &raw.header_bytes, &raw.payload, &raw.tag)
        {
            return self.violation(RefusalReason::Unauthenticated, events);
        }
        let bound = self.binding.boot().get();
        if header.boot_generation != bound {
            return self.violation(
                RefusalReason::StaleGeneration {
                    frame: header.boot_generation,
                    bound,
                },
                events,
            );
        }
        if header.connection != self.connection {
            return self.violation(
                RefusalReason::StaleConnection {
                    frame: header.connection,
                    bound: self.connection,
                },
                events,
            );
        }
        if let Err(refusal) = self.inbound.accept(header.sequence) {
            return self.violation(RefusalReason::Sequence(refusal), events);
        }
        self.last_received_at = now;
        let channel = header.channel;
        let Some(operation) = Operation::decode(channel, header.operation_code) else {
            return self.budgeted(
                RefusalReason::UnknownOperation {
                    channel,
                    code: header.operation_code,
                },
                events,
            );
        };
        if !operation
            .direction(channel)
            .is_some_and(|direction| direction.allows(Sender::Guest))
        {
            return self.budgeted(RefusalReason::WrongDirection { channel, operation }, events);
        }
        if self.state(channel).closed.is_some() {
            return self.budgeted(RefusalReason::ChannelClosed { channel }, events);
        }
        let max_message_bytes = self.limits.quota(channel).max_message_bytes;
        if raw.payload.len() > max_message_bytes as usize {
            return self.budgeted(
                RefusalReason::MessageTooLarge {
                    channel,
                    payload_bytes: raw.payload.len(),
                    max_message_bytes,
                },
                events,
            );
        }
        match (&self.phase, operation) {
            (LinkPhase::AwaitingHello, Operation::Hello) | (LinkPhase::Open, _) => {}
            (LinkPhase::AwaitingHello, operation) => {
                return self.budgeted(RefusalReason::HandshakeIncomplete { operation }, events);
            }
            (LinkPhase::Closed(_), _) => return,
        }
        if matches!(self.phase, LinkPhase::Open) && operation == Operation::Hello {
            return self.budgeted(RefusalReason::HandshakeRepeated, events);
        }
        let message = match LinkMessage::decode(
            channel,
            operation,
            header.stream,
            &raw.payload,
            max_message_bytes as usize,
        ) {
            Ok(message) => message,
            Err(refusal) => return self.budgeted(RefusalReason::Payload(refusal), events),
        };
        self.apply(message, header.sequence, now, events);
    }

    fn apply(
        &mut self,
        message: LinkMessage,
        sequence: u64,
        now: MonotonicTime,
        events: &mut Vec<LinkEvent>,
    ) {
        let vm = self.binding.vm();
        let boot = self.binding.boot();
        let connection = self.connection;
        match message {
            LinkMessage::Hello(hello) => {
                if hello.guest_version != PROTOCOL_VERSION {
                    return self.violation(
                        RefusalReason::UnsupportedGuestVersion {
                            version: hello.guest_version,
                        },
                        events,
                    );
                }
                if hello
                    .claimed_vm
                    .is_some_and(|claimed| claimed != vm.digest())
                {
                    return self.violation(
                        RefusalReason::ClaimedIdentityDisagrees {
                            field: ClaimedField::Vm,
                        },
                        events,
                    );
                }
                if hello
                    .claimed_boot
                    .is_some_and(|claimed| claimed != boot.get())
                {
                    return self.violation(
                        RefusalReason::ClaimedIdentityDisagrees {
                            field: ClaimedField::Boot,
                        },
                        events,
                    );
                }
                self.phase = LinkPhase::Open;
                let terms = WelcomeTerms {
                    version: PROTOCOL_VERSION,
                    max_frame_bytes: self.limits.max_frame_bytes,
                    idle_timeout_seconds: u32::try_from(self.limits.idle_timeout.as_secs())
                        .unwrap_or(u32::MAX),
                };
                // Welcome is urgent; the urgent queue has no budget for the link's own
                // frames, so this cannot fail.
                let _ = self.enqueue_internal(LinkMessage::Welcome(terms));
                events.push(LinkEvent::Report(GuestReport::new(
                    vm,
                    boot,
                    connection,
                    now,
                    sequence,
                    ReportBody::Hello(hello),
                )));
            }
            LinkMessage::InitReport(report) => {
                if report
                    .claimed_vm
                    .is_some_and(|claimed| claimed != vm.digest())
                {
                    return self.violation(
                        RefusalReason::ClaimedIdentityDisagrees {
                            field: ClaimedField::Vm,
                        },
                        events,
                    );
                }
                events.push(LinkEvent::Report(GuestReport::new(
                    vm,
                    boot,
                    connection,
                    now,
                    sequence,
                    ReportBody::Init(report),
                )));
            }
            LinkMessage::ProbeResult(result) => events.push(LinkEvent::Report(GuestReport::new(
                vm,
                boot,
                connection,
                now,
                sequence,
                ReportBody::Probe(result),
            ))),
            LinkMessage::AllProbesPassed(passed) => {
                events.push(LinkEvent::Report(GuestReport::new(
                    vm,
                    boot,
                    connection,
                    now,
                    sequence,
                    ReportBody::AllProbesPassed(passed),
                )))
            }
            LinkMessage::Close { reason } => {
                events.push(LinkEvent::Request(GuestRequest::Close { reason }));
                self.close_link(CloseCause::GuestClosed { reason });
                events.push(LinkEvent::Closed(CloseCause::GuestClosed { reason }));
            }
            LinkMessage::WindowUpdate {
                channel,
                credit_bytes,
            } => {
                let state = self.state_mut(channel);
                state.send_credit_bytes = state
                    .send_credit_bytes
                    .saturating_add(u64::from(credit_bytes));
                events.push(LinkEvent::Request(GuestRequest::WindowUpdate {
                    channel,
                    credit_bytes,
                }));
            }
            LinkMessage::StreamWindowUpdate {
                channel,
                stream,
                credit_bytes,
            } => {
                let state = self.state_mut(channel);
                if let Some(entry) = state.streams.get_mut(&stream.get()) {
                    entry.send_window_bytes = entry
                        .send_window_bytes
                        .saturating_add(u64::from(credit_bytes));
                } else if state.was_ended(stream.get()) {
                    // Credit that crossed the stream's finish: nothing is left to credit.
                    return;
                } else {
                    return self.missing_stream(channel, stream, events);
                }
                events.push(LinkEvent::Request(GuestRequest::StreamWindowUpdate {
                    channel,
                    stream,
                    credit_bytes,
                }));
            }
            LinkMessage::Open { stream, open } => {
                let channel = open.channel();
                if stream.opener() != Sender::Guest {
                    return self.budgeted(RefusalReason::StreamParity { stream }, events);
                }
                let state = self.state_mut(channel);
                if stream.get() <= state.highest_guest_stream {
                    let highest = state.highest_guest_stream;
                    return self.budgeted(
                        RefusalReason::StreamIdNotIncreasing { stream, highest },
                        events,
                    );
                }
                if state.streams.len() >= state.quota.max_streams as usize {
                    let max_streams = state.quota.max_streams;
                    return self.budgeted(
                        RefusalReason::StreamQuotaExceeded {
                            channel,
                            max_streams,
                        },
                        events,
                    );
                }
                match Classified::of(LinkMessage::Open { stream, open }) {
                    Classified::Request(request) => {
                        state.highest_guest_stream = stream.get();
                        state
                            .streams
                            .insert(stream.get(), StreamState::new(Sender::Guest, now));
                        events.push(LinkEvent::Request(request));
                    }
                    Classified::Report(_) | Classified::HostOnly => self.budgeted(
                        RefusalReason::WrongDirection {
                            channel,
                            operation: Operation::Open,
                        },
                        events,
                    ),
                }
            }
            LinkMessage::Opened { channel, stream }
            | LinkMessage::OpenRefused {
                channel, stream, ..
            } => {
                let opened = matches!(message, LinkMessage::Opened { .. });
                let state = self.state_mut(channel);
                match state.streams.get(&stream.get()) {
                    Some(entry) if entry.opener == Sender::Host && !entry.open => {}
                    Some(_) => {
                        return self
                            .budgeted(RefusalReason::StreamNotOpening { channel, stream }, events)
                    }
                    None => return self.missing_stream(channel, stream, events),
                }
                if opened {
                    if let Some(entry) = state.streams.get_mut(&stream.get()) {
                        entry.open = true;
                    }
                } else {
                    state.complete(stream.get());
                }
                if let Classified::Request(request) = Classified::of(message) {
                    events.push(LinkEvent::Request(request));
                }
            }
            LinkMessage::Data {
                channel,
                stream,
                bytes,
            } => {
                let state = self.state_mut(channel);
                let entry = match state.streams.get(&stream.get()) {
                    Some(entry) if entry.open => *entry,
                    Some(_) => {
                        return self
                            .budgeted(RefusalReason::StreamNotOpen { channel, stream }, events)
                    }
                    None if state.was_cancelled(stream.get()) => {
                        return self.cancelled_data(channel, stream, bytes.len() as u64, events)
                    }
                    None => return self.missing_stream(channel, stream, events),
                };
                if entry.guest_ended {
                    return self.budgeted(RefusalReason::HalfClosed { channel, stream }, events);
                }
                let needed_bytes = bytes.len() as u64;
                if channel.has_stream_windows() {
                    let remaining_bytes = entry.receive_window_bytes;
                    if needed_bytes > remaining_bytes {
                        return self.channel_violation(
                            channel,
                            ChannelCloseCause::StreamWindowExceeded {
                                stream,
                                remaining_bytes,
                                needed_bytes,
                            },
                            RefusalReason::StreamWindowExceeded {
                                channel,
                                stream,
                                remaining_bytes,
                                needed_bytes,
                            },
                            events,
                        );
                    }
                    if let Some(entry) = state.streams.get_mut(&stream.get()) {
                        entry.receive_window_bytes -= needed_bytes;
                        entry.buffered_bytes += needed_bytes;
                    }
                    events.push(LinkEvent::Request(GuestRequest::Data {
                        channel,
                        stream,
                        bytes,
                    }));
                    return;
                }
                let remaining_bytes = state.receive_window_bytes;
                if needed_bytes > remaining_bytes {
                    return self.channel_violation(
                        channel,
                        ChannelCloseCause::WindowExceeded {
                            remaining_bytes,
                            needed_bytes,
                        },
                        RefusalReason::WindowExceeded {
                            channel,
                            remaining_bytes,
                            needed_bytes,
                        },
                        events,
                    );
                }
                state.receive_window_bytes -= needed_bytes;
                state.buffered_bytes += needed_bytes;
                events.push(LinkEvent::Request(GuestRequest::Data {
                    channel,
                    stream,
                    bytes,
                }));
            }
            LinkMessage::EndOfStream { channel, stream } => {
                if let Some(refusal) = self.guest_end(channel, stream) {
                    return self.refuse_end(channel, stream, refusal, events);
                }
                events.push(LinkEvent::Request(GuestRequest::EndOfStream {
                    channel,
                    stream,
                }));
            }
            LinkMessage::Exit { stream, code } => {
                let channel = Channel::Terminal;
                if let Some(refusal) = self.guest_end(channel, stream) {
                    return self.refuse_end(channel, stream, refusal, events);
                }
                events.push(LinkEvent::Report(GuestReport::new(
                    vm,
                    boot,
                    connection,
                    now,
                    sequence,
                    ReportBody::TerminalExit { stream, code },
                )));
            }
            LinkMessage::Cancel {
                channel,
                stream,
                cause,
            } => {
                let state = self.state_mut(channel);
                if !state.streams.contains_key(&stream.get()) {
                    return self.missing_stream(channel, stream, events);
                }
                state.forget(stream.get());
                events.push(LinkEvent::Request(GuestRequest::Cancel {
                    channel,
                    stream,
                    cause,
                }));
            }
            LinkMessage::Ping { nonce } => {
                events.push(LinkEvent::Request(GuestRequest::Ping { nonce }))
            }
            LinkMessage::Pong { nonce } => {
                events.push(LinkEvent::Request(GuestRequest::Pong { nonce }))
            }
            LinkMessage::Challenge { .. }
            | LinkMessage::Welcome(_)
            | LinkMessage::Revoke(_)
            | LinkMessage::Shutdown(_)
            | LinkMessage::Resize { .. } => self.budgeted(
                RefusalReason::WrongDirection {
                    channel: message.channel(),
                    operation: message.operation(),
                },
                events,
            ),
        }
    }

    /// Marks the guest's direction of a stream ended; `None` on success.
    fn guest_end(&mut self, channel: Channel, stream: StreamId) -> Option<EndRefusal> {
        let state = self.state_mut(channel);
        let entry = match state.streams.get(&stream.get()) {
            Some(entry) if entry.open => *entry,
            Some(_) => return Some(EndRefusal::NotOpen),
            None => return Some(EndRefusal::Missing),
        };
        if entry.guest_ended {
            return Some(EndRefusal::HalfClosed);
        }
        if entry.host_ended {
            state.complete(stream.get());
        } else if let Some(entry) = state.streams.get_mut(&stream.get()) {
            entry.guest_ended = true;
        }
        None
    }

    fn refuse_end(
        &mut self,
        channel: Channel,
        stream: StreamId,
        refusal: EndRefusal,
        events: &mut Vec<LinkEvent>,
    ) {
        match refusal {
            EndRefusal::HalfClosed => {
                self.budgeted(RefusalReason::HalfClosed { channel, stream }, events)
            }
            EndRefusal::NotOpen => {
                self.budgeted(RefusalReason::StreamNotOpen { channel, stream }, events)
            }
            EndRefusal::Missing => self.missing_stream(channel, stream, events),
        }
    }

    /// Guest data for a stream that was cancelled, sent before the guest learned of it: it
    /// counts against the receive window like any data (an overrun closes the channel),
    /// is dropped, and its bytes are credited back to the guest at once, since the guest
    /// spent its credit on them and nothing will consume them. The frame is refused
    /// without charging the budget.
    fn cancelled_data(
        &mut self,
        channel: Channel,
        stream: StreamId,
        needed_bytes: u64,
        events: &mut Vec<LinkEvent>,
    ) {
        if channel.has_stream_windows() {
            // The stream's window went with the stream: nothing is held or credited.
            events.push(LinkEvent::Refused(Refusal {
                reason: RefusalReason::StreamCancelled { channel, stream },
                effect: RefusalEffect::FrameDropped,
            }));
            return;
        }
        let remaining_bytes = self.state(channel).receive_window_bytes;
        if needed_bytes > remaining_bytes {
            return self.channel_violation(
                channel,
                ChannelCloseCause::WindowExceeded {
                    remaining_bytes,
                    needed_bytes,
                },
                RefusalReason::WindowExceeded {
                    channel,
                    remaining_bytes,
                    needed_bytes,
                },
                events,
            );
        }
        let state = self.state_mut(channel);
        state.receive_window_bytes -= needed_bytes;
        state.held_credit_bytes = state.held_credit_bytes.saturating_add(needed_bytes);
        self.return_held_credit(channel);
        events.push(LinkEvent::Refused(Refusal {
            reason: RefusalReason::StreamCancelled { channel, stream },
            effect: RefusalEffect::FrameDropped,
        }));
    }

    /// A frame for a stream the channel does not hold: a cancelled stream's late frames
    /// are refused without charging the budget, since they may have been in flight.
    fn missing_stream(&mut self, channel: Channel, stream: StreamId, events: &mut Vec<LinkEvent>) {
        if self.state(channel).was_cancelled(stream.get()) {
            events.push(LinkEvent::Refused(Refusal {
                reason: RefusalReason::StreamCancelled { channel, stream },
                effect: RefusalEffect::FrameDropped,
            }));
        } else {
            self.budgeted(RefusalReason::StreamNotOpen { channel, stream }, events);
        }
    }

    /// A refusal that closes the link.
    fn violation(&mut self, reason: RefusalReason, events: &mut Vec<LinkEvent>) {
        events.push(LinkEvent::Refused(Refusal {
            reason: reason.clone(),
            effect: RefusalEffect::LinkClosed,
        }));
        self.close_link(CloseCause::Violation(reason.clone()));
        events.push(LinkEvent::Closed(CloseCause::Violation(reason)));
    }

    /// A refusal charged to the budget; exhausting it closes the link.
    fn budgeted(&mut self, reason: RefusalReason, events: &mut Vec<LinkEvent>) {
        self.refusals = self.refusals.saturating_add(1);
        if self.refusals >= self.limits.max_refusals {
            let cause = CloseCause::RefusalBudgetExhausted {
                max_refusals: self.limits.max_refusals,
            };
            events.push(LinkEvent::Refused(Refusal {
                reason,
                effect: RefusalEffect::LinkClosed,
            }));
            self.close_link(cause.clone());
            events.push(LinkEvent::Closed(cause));
        } else {
            events.push(LinkEvent::Refused(Refusal {
                reason,
                effect: RefusalEffect::FrameDropped,
            }));
        }
    }

    /// A refusal that closes one bulk channel: its streams and queue are dropped.
    fn channel_violation(
        &mut self,
        channel: Channel,
        cause: ChannelCloseCause,
        reason: RefusalReason,
        events: &mut Vec<LinkEvent>,
    ) {
        let state = self.state_mut(channel);
        state.closed = Some(cause);
        state.clear();
        events.push(LinkEvent::Refused(Refusal {
            reason,
            effect: RefusalEffect::ChannelClosed { channel },
        }));
        events.push(LinkEvent::ChannelClosed { channel, cause });
    }

    /// Closes the link: no frame is read again, every queue is dropped, and one close
    /// frame is queued for the guest.
    fn close_link(&mut self, cause: CloseCause) {
        if self.is_closed() {
            return;
        }
        let reason = cause.close_reason();
        self.phase = LinkPhase::Closed(cause);
        self.decoder.close(FramingRefusal::DecoderClosed);
        self.urgent.clear();
        for state in &mut self.channels {
            state.clear();
        }
        let _ = self.enqueue_internal(LinkMessage::Close { reason });
    }
}

enum EndRefusal {
    HalfClosed,
    NotOpen,
    Missing,
}

impl<C: Clock> fmt::Debug for HostLink<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostLink")
            .field("binding", &self.binding)
            .field("connection", &self.connection)
            .field("phase", &self.phase)
            .field("inbound", &self.inbound)
            .field("outbound", &self.outbound)
            .field("refusals", &self.refusals)
            .field("decoder", &self.decoder.phase())
            .field("queued_frames", &self.queued_frames())
            .finish()
    }
}
