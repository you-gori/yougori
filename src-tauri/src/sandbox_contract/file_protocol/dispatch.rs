//! The file channel's dispatcher (VM part §3.2: "fixed maximum frame, message, stream and
//! buffered-byte counts", "backpressure", "independent quotas for control, terminal,
//! file, ingress and egress channels", "Never trust a guest-supplied sandbox ID as the
//! source of identity"; §5.1; VM-W14).
//!
//! A [`FileDispatcher`] serves one guest channel over one grant's [`FileService`]. The
//! transport that authenticated the channel (VM-W06) gives it the channel's
//! [`TrustScope`], which must be the grant's; the host gives it its clock and that
//! clock's [`ClockSession`], the one grants are stamped on. For every request it builds
//! the [`RequestContext`] from those alone, reading the time when it performs the request;
//! nothing in a guest message can name a scope, time, session or root (the strict header
//! refuses any such field), so a message cannot change what the grant authorizes.
//!
//! [`FileDispatcher::receive`] takes one message: it buffers a part of a create's or
//! write's content, admits a whole request, answers a refused message with a
//! [`ProtocolRefusal`] without touching the service, or drops the message.
//! [`FileDispatcher::perform`] calls the service once for an admitted request. The halves
//! let a transport queue requests; [`FileDispatcher::dispatch`] does both at once.
//!
//! Bounds per channel ([`ChannelLimits`]), counted and refused when exceeded:
//!
//! - Messages: every message received and sent is at most `max_message_bytes`; content
//!   that does not fit one message travels in numbered parts.
//! - Requests in flight: being received, or admitted and not yet performed or cancelled.
//! - Content: one request's content, either way, is held whole by the host, so it is at
//!   most `max_buffered_bytes`, and the content of requests being received together is too.
//! - Bytes per window. Every message received counts at least
//!   [`MIN_MESSAGE_COST_BYTES`]. Admitting a request reserves the most its answer can take
//!   (a read's limit, a listing's worst case), and the answer replaces the reservation
//!   when it is made. Every refusal is counted when it is made. Windows are fixed and
//!   start at the first count after the previous one ended, the rule of
//!   `foundation::events`' `RateLimiter`, which counts events and not bytes. The first
//!   message that does not fit a window gets its one
//!   [`ProtocolRefusal::ByteWindowExceeded`]; every later message that does not fit it is
//!   dropped unanswered and counted. A window therefore carries at most its bound, one
//!   refusal of a message that fit, and that one window refusal, plus the answers to
//!   requests admitted in the window before, which are counted in full where they are
//!   made and were bounded by their reservations where they were admitted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::parts::EncodeError;
use super::refusal::ProtocolRefusal;
use super::request::{
    bytes_of, GuestOperation, GuestRequest, RequestId, RequestPart, DEFAULT_MAX_MESSAGE_BYTES,
    MAX_CONTENT_BYTES, MAX_MESSAGE_BYTES, MIN_MESSAGE_BYTES,
};
use super::response::{Completed, FileResponse, ResponseOutcome, MAX_LISTED_ENTRY_BYTES};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Clock, MonotonicTime, TrustScope};
use crate::sandbox_contract::files::{FileService, RequestContext, MAX_LISTED_ENTRIES};

/// The least a received message counts against the window, about the size of the refusal
/// it may get, so empty and tiny messages cannot pass uncounted.
pub const MIN_MESSAGE_COST_BYTES: u64 = 256;
/// The default bound on one request's content and on the content of requests being
/// received together: 8 MiB, the link's file channel buffer (`sandbox/link/limits.rs`),
/// stated by value.
pub const DEFAULT_MAX_BUFFERED_BYTES: u64 = 8 * 1024 * 1024;
/// The default bytes per window: two buffers' worth.
pub const DEFAULT_MAX_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
/// The default requests being received or in flight at once.
pub const DEFAULT_MAX_IN_FLIGHT: u32 = 16;
/// The most an answer without content or entries takes, such as a service refusal naming
/// two of the longest names.
pub(super) const REPLY_RESERVE_BYTES: u64 = 4096;
/// The most one part's header line takes beside its content or entries.
pub(super) const PART_HEADER_BYTES: u64 = 256;

/// Numbers every dispatcher of this process, so an admission is honoured only by the
/// dispatcher that made it.
static NEXT_CHANNEL: AtomicU64 = AtomicU64::new(1);

/// The bounds of one file channel (VM part §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelLimits {
    /// The most requests being received or admitted and not yet performed or cancelled.
    pub max_in_flight: u32,
    /// The most bytes counted in one window. A read whose answer cannot fit an empty
    /// window is never admitted.
    pub max_window_bytes: u64,
    /// The window's length on the host clock.
    pub window: Duration,
    /// The longest message either way, from [`MIN_MESSAGE_BYTES`] to [`MAX_MESSAGE_BYTES`].
    pub max_message_bytes: u64,
    /// The most content one request carries, and the most the content of requests being
    /// received together holds.
    pub max_buffered_bytes: u64,
}

impl Default for ChannelLimits {
    fn default() -> Self {
        Self {
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            max_window_bytes: DEFAULT_MAX_WINDOW_BYTES,
            window: Duration::from_secs(1),
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
        }
    }
}

impl ChannelLimits {
    /// Refuses a bound of zero, a message bound outside its range, and a window that could
    /// not admit a listing.
    pub fn validate(&self) -> Result<(), ChannelProblem> {
        if self.max_in_flight == 0 {
            return Err(ChannelProblem::ZeroInFlight);
        }
        if self.window.is_zero() {
            return Err(ChannelProblem::ZeroWindow);
        }
        if !(MIN_MESSAGE_BYTES..=MAX_MESSAGE_BYTES).contains(&self.max_message_bytes) {
            return Err(ChannelProblem::MessageBoundOutOfRange {
                max_message_bytes: self.max_message_bytes,
                minimum: MIN_MESSAGE_BYTES,
                maximum: MAX_MESSAGE_BYTES,
            });
        }
        if self.max_buffered_bytes == 0 {
            return Err(ChannelProblem::ZeroBuffer);
        }
        let minimum = self.listing_reservation();
        if self.max_window_bytes < minimum {
            return Err(ChannelProblem::WindowTooSmall {
                max_window_bytes: self.max_window_bytes,
                minimum,
            });
        }
        Ok(())
    }

    /// The most content one request carries on this channel.
    pub fn content_limit(&self) -> u64 {
        self.max_buffered_bytes.min(MAX_CONTENT_BYTES)
    }

    /// Parts needed for `bytes` when each part leaves `slack` of its room unused.
    fn parts_for(&self, bytes: u64, slack: u64) -> u64 {
        let room = self
            .max_message_bytes
            .saturating_sub(PART_HEADER_BYTES.saturating_add(slack))
            .max(1);
        bytes.div_ceil(room).saturating_add(1)
    }

    /// The most a listing's answer takes: every entry of the longest kind, in pages.
    pub fn listing_reservation(&self) -> u64 {
        let per_entry = MAX_LISTED_ENTRY_BYTES.saturating_add(1);
        let entries = u64::try_from(MAX_LISTED_ENTRIES)
            .unwrap_or(u64::MAX)
            .saturating_mul(per_entry);
        entries
            .saturating_add(
                self.parts_for(entries, per_entry)
                    .saturating_mul(PART_HEADER_BYTES),
            )
            .saturating_add(REPLY_RESERVE_BYTES)
    }

    /// What admitting `operation` reserves in the window for its answer.
    pub fn reply_reservation(&self, operation: &GuestOperation) -> u64 {
        match operation {
            GuestOperation::Read { max_bytes, .. } | GuestOperation::ReadRange { max_bytes, .. } => {
                max_bytes
                    .saturating_add(
                        self.parts_for(*max_bytes, 0)
                            .saturating_mul(PART_HEADER_BYTES),
                    )
                    .saturating_add(REPLY_RESERVE_BYTES)
            }
            GuestOperation::List { .. } => self.listing_reservation(),
            _ => REPLY_RESERVE_BYTES,
        }
    }
}

/// Why a channel could not be set up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ChannelProblem {
    /// No request could be in flight.
    ZeroInFlight,
    /// A window of no length.
    ZeroWindow,
    /// The message bound is outside its range.
    MessageBoundOutOfRange {
        /// The bound asked for.
        max_message_bytes: u64,
        /// [`MIN_MESSAGE_BYTES`].
        minimum: u64,
        /// [`MAX_MESSAGE_BYTES`].
        maximum: u64,
    },
    /// No content could be carried.
    ZeroBuffer,
    /// The window could never admit a listing.
    WindowTooSmall {
        /// The window asked for.
        max_window_bytes: u64,
        /// What a listing reserves.
        minimum: u64,
    },
    /// The channel's authenticated scope is not the grant's.
    ScopeMismatch,
}

impl fmt::Display for ChannelProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroInFlight => f.write_str("a channel needs room for one request in flight"),
            Self::ZeroWindow => f.write_str("a channel's window cannot be zero long"),
            Self::MessageBoundOutOfRange {
                max_message_bytes,
                minimum,
                maximum,
            } => write!(
                f,
                "a message bound of {max_message_bytes} bytes is outside {minimum}..={maximum}"
            ),
            Self::ZeroBuffer => f.write_str("a channel's buffer needs room for one byte"),
            Self::WindowTooSmall {
                max_window_bytes,
                minimum,
            } => write!(
                f,
                "a window of {max_window_bytes} bytes cannot admit a listing, which reserves \
                 {minimum}"
            ),
            Self::ScopeMismatch => f.write_str("the channel's scope is not the grant's"),
        }
    }
}

impl std::error::Error for ChannelProblem {}

/// What one channel has counted since it was made.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ChannelCounters {
    /// Messages offered to [`FileDispatcher::receive`].
    pub received: u64,
    /// Parts of a create's or write's content held until the content is whole.
    pub buffered_parts: u64,
    /// Whole requests admitted.
    pub admitted: u64,
    /// Admitted requests the service was called for.
    pub performed: u64,
    /// Admitted or partly received requests given back unperformed.
    pub cancelled: u64,
    /// Messages refused as oversized, malformed, unknown, of another version, with an
    /// invalid name or content, out of order, or with an id already in use.
    pub message_refusals: u64,
    /// Requests refused because the channel held its most in flight.
    pub in_flight_refusals: u64,
    /// Messages and reservations refused because the window was spent.
    pub byte_window_refusals: u64,
    /// Messages dropped unanswered after the window's refusal.
    pub dropped: u64,
    /// Message bytes counted against the window.
    pub received_bytes: u64,
    /// Bytes of dropped messages.
    pub dropped_bytes: u64,
    /// Response bytes counted against the window.
    pub sent_bytes: u64,
}

/// What [`FileDispatcher::receive`] made of one message.
#[derive(Debug)]
#[must_use = "an admitted request must be performed or cancelled, and a refusal sent"]
pub enum Received {
    /// A whole request, admitted: give it to [`FileDispatcher::perform`] or
    /// [`FileDispatcher::cancel`].
    Admitted(Admitted),
    /// A part of a create's or write's content was buffered; its request continues.
    Buffered,
    /// The message was refused; send this.
    Refused(FileResponse),
    /// The window is spent and its one refusal was sent; nothing is sent.
    Dropped,
}

/// A whole request admitted on one channel. It holds an in-flight slot until it is given
/// back to [`FileDispatcher::perform`] or [`FileDispatcher::cancel`]; dropped, the slot
/// stays taken.
#[derive(Debug)]
#[must_use = "an admitted request holds an in-flight slot until it is performed or cancelled"]
pub struct Admitted {
    channel: u64,
    request: GuestRequest,
    reserved: u64,
    window: u64,
}

impl Admitted {
    /// The request, such as for a transport's scheduling.
    pub fn request(&self) -> &GuestRequest {
        &self.request
    }
}

/// A create or write whose content is still arriving.
#[derive(Debug)]
struct Receiving {
    operation: GuestOperation,
    declared: u64,
    received: u64,
    next_part: u32,
    reserved: u64,
    window: u64,
}

/// Fixed byte windows on the host clock.
#[derive(Clone, Copy, Debug, Default)]
struct ByteWindow {
    started: Option<MonotonicTime>,
    used: u64,
    /// Which window this is, so a reservation is returned only to the window it was
    /// taken from.
    number: u64,
    /// The window whose one refusal was sent.
    refused_in: Option<u64>,
}

impl ByteWindow {
    /// Starts a new window at `now` unless the current one is still open.
    fn roll(&mut self, now: MonotonicTime, length: Duration) {
        let open = self
            .started
            .is_some_and(|started| now.saturating_duration_since(started) < length);
        if !open {
            self.started = Some(now);
            self.used = 0;
            self.number = self.number.wrapping_add(1);
        }
    }

    /// Counts `bytes`, or refuses them and counts nothing.
    fn count(
        &mut self,
        now: MonotonicTime,
        bytes: u64,
        limits: &ChannelLimits,
    ) -> Result<(), ProtocolRefusal> {
        self.roll(now, limits.window);
        let total = self.used.saturating_add(bytes);
        if total > limits.max_window_bytes {
            let elapsed = self.started.map_or(Duration::ZERO, |started| {
                now.saturating_duration_since(started)
            });
            let remaining = limits.window.saturating_sub(elapsed);
            return Err(ProtocolRefusal::ByteWindowExceeded {
                used_bytes: self.used,
                requested_bytes: bytes,
                limit_bytes: limits.max_window_bytes,
                retry_after_ms: u64::try_from(remaining.as_nanos().div_ceil(1_000_000))
                    .unwrap_or(u64::MAX),
            });
        }
        self.used = total;
        Ok(())
    }

    /// Whether this window's one refusal is still to be sent; it is then taken.
    fn take_refusal(&mut self) -> bool {
        if self.refused_in == Some(self.number) {
            return false;
        }
        self.refused_in = Some(self.number);
        true
    }

    /// Replaces the reservation taken in window `number` by `bytes`, counted whatever the
    /// bound; a reservation from an earlier window ended with it.
    fn settle(
        &mut self,
        now: MonotonicTime,
        number: Option<u64>,
        reserved: u64,
        bytes: u64,
        length: Duration,
    ) {
        self.roll(now, length);
        if number == Some(self.number) {
            self.used = self.used.saturating_sub(reserved);
        }
        self.used = self.used.saturating_add(bytes);
    }
}

/// The dispatcher of one guest file channel over one grant's [`FileService`].
pub struct FileDispatcher<C: Clock> {
    service: FileService,
    scope: TrustScope,
    clock: C,
    session: ClockSession,
    limits: ChannelLimits,
    channel: u64,
    in_flight: BTreeSet<RequestId>,
    receiving: BTreeMap<RequestId, Receiving>,
    buffered: u64,
    window: ByteWindow,
    counters: ChannelCounters,
}

impl<C: Clock> FileDispatcher<C> {
    /// A dispatcher for the channel the transport authenticated as `scope`, which must be
    /// the grant's, serving `service`. `clock` and `session` are the pair the coordinator
    /// holds (`Coordinator::new(clock, session, ..)`, `Coordinator::session`): the grant
    /// was stamped with that session, and a reading of another clock or session never
    /// authorizes. `foundation::ids` has no type pairing them.
    pub fn new(
        service: FileService,
        scope: TrustScope,
        clock: C,
        session: ClockSession,
        limits: ChannelLimits,
    ) -> Result<Self, ChannelProblem> {
        limits.validate()?;
        if service.grant().scope() != scope {
            return Err(ChannelProblem::ScopeMismatch);
        }
        Ok(Self {
            service,
            scope,
            clock,
            session,
            limits,
            channel: NEXT_CHANNEL.fetch_add(1, Ordering::Relaxed),
            in_flight: BTreeSet::new(),
            receiving: BTreeMap::new(),
            buffered: 0,
            window: ByteWindow::default(),
            counters: ChannelCounters::default(),
        })
    }

    /// The service.
    pub fn service(&self) -> &FileService {
        &self.service
    }

    /// The service, such as to recount the root after the user changed it.
    pub fn service_mut(&mut self) -> &mut FileService {
        &mut self.service
    }

    /// The service, ending the channel.
    pub fn into_service(self) -> FileService {
        self.service
    }

    /// The scope every request on this channel is made as.
    pub fn scope(&self) -> TrustScope {
        self.scope
    }

    /// The channel's bounds.
    pub fn limits(&self) -> ChannelLimits {
        self.limits
    }

    /// What the channel has counted.
    pub fn counters(&self) -> ChannelCounters {
        self.counters
    }

    /// Requests admitted and not yet performed or cancelled.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Requests whose content is still arriving, such as for a host timeout to cancel.
    pub fn incomplete(&self) -> impl Iterator<Item = RequestId> + '_ {
        self.receiving.keys().copied()
    }

    /// Content bytes declared by the requests being received.
    pub fn buffered_bytes(&self) -> u64 {
        self.buffered
    }

    /// Bytes counted in the window as of the last count.
    pub fn window_bytes(&self) -> u64 {
        self.window.used
    }

    /// `response` as the messages to send, each within the channel's message bound.
    pub fn encode(&self, response: &FileResponse) -> Result<Vec<Vec<u8>>, EncodeError> {
        response.encode(self.limits.max_message_bytes)
    }

    /// Counts `response` against the window in place of `reserved`, taken in window
    /// `number`. A response that cannot be encoded counts as `u64::MAX`, spending the
    /// window; the transport's encode then fails as well.
    fn count_response(&mut self, response: &FileResponse, number: Option<u64>, reserved: u64) {
        let sent = response
            .encoded_len(self.limits.max_message_bytes)
            .unwrap_or(u64::MAX);
        self.window
            .settle(self.clock.now(), number, reserved, sent, self.limits.window);
        self.counters.sent_bytes = self.counters.sent_bytes.saturating_add(sent);
    }

    /// A counted refusal of a message that claimed `claimed`.
    fn refusal(&mut self, claimed: Option<RequestId>, refusal: ProtocolRefusal) -> Received {
        let response = FileResponse::refusal(claimed, refusal);
        self.count_response(&response, None, 0);
        Received::Refused(response)
    }

    fn refuse_message(&mut self, claimed: Option<RequestId>, refusal: ProtocolRefusal) -> Received {
        self.counters.message_refusals = self.counters.message_refusals.saturating_add(1);
        self.refusal(claimed, refusal)
    }

    fn refuse_bytes(&mut self, claimed: Option<RequestId>, refusal: ProtocolRefusal) -> Received {
        self.counters.byte_window_refusals = self.counters.byte_window_refusals.saturating_add(1);
        self.refusal(claimed, refusal)
    }

    /// Takes one message. In order: the window (counting at least
    /// [`MIN_MESSAGE_COST_BYTES`]), the message bound, decoding, then for a first part the
    /// id, the requests in flight, the content bounds and the answer's reservation, or for
    /// a later part the request it continues.
    pub fn receive(&mut self, payload: &[u8]) -> Received {
        self.counters.received = self.counters.received.saturating_add(1);
        let now = self.clock.now();
        let length = bytes_of(payload.len());
        let cost = length.max(MIN_MESSAGE_COST_BYTES);
        if let Err(refusal) = self.window.count(now, cost, &self.limits) {
            if !self.window.take_refusal() {
                self.counters.dropped = self.counters.dropped.saturating_add(1);
                self.counters.dropped_bytes = self.counters.dropped_bytes.saturating_add(length);
                return Received::Dropped;
            }
            return self.refuse_bytes(None, refusal);
        }
        self.counters.received_bytes = self.counters.received_bytes.saturating_add(cost);
        if length > self.limits.max_message_bytes {
            return self.refuse_message(
                None,
                ProtocolRefusal::MessageTooLarge {
                    bytes: length,
                    limit: self.limits.max_message_bytes,
                },
            );
        }
        match RequestPart::decode(payload) {
            Err(undecoded) => self.refuse_message(undecoded.claimed_request_id, undecoded.refusal),
            Ok(RequestPart::Opening {
                id,
                operation,
                declared_length,
            }) => self.open(now, id, operation, declared_length),
            Ok(RequestPart::Continuation { id, part, content }) => {
                self.continue_request(id, part, &content)
            }
        }
    }

    fn open(
        &mut self,
        now: MonotonicTime,
        id: RequestId,
        operation: GuestOperation,
        declared: u64,
    ) -> Received {
        let claimed = Some(id);
        if self.in_flight.contains(&id) || self.receiving.contains_key(&id) {
            return self.refuse_message(claimed, ProtocolRefusal::DuplicateRequestId);
        }
        let held = self.in_flight.len().saturating_add(self.receiving.len());
        if held >= usize::try_from(self.limits.max_in_flight).unwrap_or(usize::MAX) {
            self.counters.in_flight_refusals = self.counters.in_flight_refusals.saturating_add(1);
            let limit = self.limits.max_in_flight;
            return self.refusal(claimed, ProtocolRefusal::TooManyInFlight { limit });
        }
        let limit = self.limits.content_limit();
        if let GuestOperation::Read { max_bytes, .. } | GuestOperation::ReadRange { max_bytes, .. } = &operation {
            if *max_bytes > limit {
                let max_bytes = *max_bytes;
                return self.refuse_message(
                    claimed,
                    ProtocolRefusal::ReadLimitTooLarge { max_bytes, limit },
                );
            }
        }
        if declared > limit {
            return self.refuse_message(
                claimed,
                ProtocolRefusal::ContentTooLarge {
                    length: declared,
                    limit,
                },
            );
        }
        let first = bytes_of(operation.content().map_or(0, <[u8]>::len));
        let continues = declared > first;
        if continues && self.buffered.saturating_add(declared) > self.limits.max_buffered_bytes {
            let buffered = self.buffered;
            let limit = self.limits.max_buffered_bytes;
            return self.refuse_message(
                claimed,
                ProtocolRefusal::BufferFull {
                    declared,
                    buffered,
                    limit,
                },
            );
        }
        let reserved = self.limits.reply_reservation(&operation);
        if let Err(refusal) = self.window.count(now, reserved, &self.limits) {
            return self.refuse_bytes(claimed, refusal);
        }
        let window = self.window.number;
        if continues {
            self.buffered = self.buffered.saturating_add(declared);
            self.counters.buffered_parts = self.counters.buffered_parts.saturating_add(1);
            self.receiving.insert(
                id,
                Receiving {
                    operation,
                    declared,
                    received: first,
                    next_part: 1,
                    reserved,
                    window,
                },
            );
            return Received::Buffered;
        }
        self.admit(id, operation, reserved, window)
    }

    fn admit(
        &mut self,
        id: RequestId,
        operation: GuestOperation,
        reserved: u64,
        window: u64,
    ) -> Received {
        self.in_flight.insert(id);
        self.counters.admitted = self.counters.admitted.saturating_add(1);
        Received::Admitted(Admitted {
            channel: self.channel,
            request: GuestRequest { id, operation },
            reserved,
            window,
        })
    }

    /// Discards a request being received, freeing its buffer and slot.
    fn discard(&mut self, id: RequestId) -> Option<Receiving> {
        let receiving = self.receiving.remove(&id)?;
        self.buffered = self.buffered.saturating_sub(receiving.declared);
        Some(receiving)
    }

    fn continue_request(&mut self, id: RequestId, part: u32, content: &[u8]) -> Received {
        let claimed = Some(id);
        let Some((expected, declared, so_far)) = self
            .receiving
            .get(&id)
            .map(|receiving| (receiving.next_part, receiving.declared, receiving.received))
        else {
            return self.refuse_message(claimed, ProtocolRefusal::UnexpectedPart);
        };
        if part != expected {
            self.discard(id);
            return self.refuse_message(
                claimed,
                ProtocolRefusal::PartOutOfOrder {
                    expected,
                    received: part,
                },
            );
        }
        let received = so_far.saturating_add(bytes_of(content.len()));
        if received > declared {
            self.discard(id);
            return self.refuse_message(
                claimed,
                ProtocolRefusal::LengthMismatch {
                    declared,
                    actual: received,
                },
            );
        }
        if let Some(receiving) = self.receiving.get_mut(&id) {
            if let Some(buffer) = receiving.operation.content_mut() {
                buffer.extend_from_slice(content);
            }
            receiving.received = received;
            receiving.next_part = expected.saturating_add(1);
        }
        self.counters.buffered_parts = self.counters.buffered_parts.saturating_add(1);
        if received < declared {
            return Received::Buffered;
        }
        match self.discard(id) {
            Some(done) => self.admit(id, done.operation, done.reserved, done.window),
            None => self.refuse_message(claimed, ProtocolRefusal::UnexpectedPart),
        }
    }

    /// Whether `admitted` was made here and is still in flight; it is then no longer.
    fn release(&mut self, admitted: &Admitted) -> bool {
        admitted.channel == self.channel && self.in_flight.remove(&admitted.request.id)
    }

    /// The refusal of an admission this channel does not hold, counted.
    fn not_admitted(&mut self, admitted: &Admitted) -> FileResponse {
        let response =
            FileResponse::refusal(Some(admitted.request.id), ProtocolRefusal::NotAdmitted);
        self.count_response(&response, None, 0);
        response
    }

    /// Performs an admitted request with one service call, as the channel's scope at the
    /// host clock's reading now.
    pub fn perform(&mut self, admitted: Admitted) -> FileResponse {
        if !self.release(&admitted) {
            return self.not_admitted(&admitted);
        }
        let context = RequestContext {
            scope: self.scope,
            now: self.clock.now(),
            session: self.session,
        };
        let service = &mut self.service;
        let result = match &admitted.request.operation {
            GuestOperation::Read { name, max_bytes } => service
                .read(&context, name, *max_bytes)
                .map(|content| Completed::Read { content }),
            GuestOperation::ReadRange {
                name,
                offset,
                max_bytes,
                upload: None,
            } => service
                .read_range(&context, name, *offset, *max_bytes)
                .map(|read| Completed::RangeRead {
                    content: read.content,
                    size_bytes: read.size_bytes,
                    version: read.version,
                }),
            GuestOperation::ReadRange {
                name,
                offset,
                max_bytes,
                upload: Some(upload),
            } => service
                .read_upload_range(&context, name, *upload, *offset, *max_bytes)
                .map(|read| Completed::RangeRead {
                    content: read.content,
                    size_bytes: read.size_bytes,
                    version: read.version,
                }),
            GuestOperation::UploadBegin {
                name,
                from_existing,
            } => service
                .upload_begin(&context, name, *from_existing)
                .map(|(upload, size_bytes)| Completed::UploadBegun { upload, size_bytes }),
            GuestOperation::UploadWrite {
                name,
                upload,
                offset,
                content,
            } => service
                .upload_write(&context, name, *upload, *offset, content)
                .map(|size_bytes| Completed::UploadWritten { size_bytes }),
            GuestOperation::UploadTruncate {
                name,
                upload,
                length,
            } => service
                .upload_truncate(&context, name, *upload, *length)
                .map(|size_bytes| Completed::UploadWritten { size_bytes }),
            GuestOperation::UploadCommit { name, upload } => service
                .upload_commit(&context, name, *upload)
                .map(|(size_bytes, content)| Completed::UploadCommitted { size_bytes, content }),
            GuestOperation::UploadAbort { name, upload } => service
                .upload_abort(&context, name, *upload)
                .map(|()| Completed::UploadAborted),
            GuestOperation::List { name } => service
                .list(&context, name.as_ref())
                .map(|listing| Completed::Listed { listing }),
            GuestOperation::Create { name, content } => service
                .create(&context, name, content)
                .map(|()| Completed::Created),
            GuestOperation::CreateDirectory { name } => service
                .create_directory(&context, name)
                .map(|()| Completed::DirectoryCreated),
            GuestOperation::Write { name, content } => service
                .write(&context, name, content)
                .map(|()| Completed::Written),
            GuestOperation::Delete { name } => {
                service.delete(&context, name).map(|()| Completed::Deleted)
            }
            GuestOperation::Rename {
                from,
                to,
                replace: false,
            } => service
                .rename(&context, from, to)
                .map(|()| Completed::Renamed),
            GuestOperation::Rename {
                from,
                to,
                replace: true,
            } => service
                .rename_replacing(&context, from, to)
                .map(|()| Completed::Renamed),
            GuestOperation::SetExecutable { name, executable } => service
                .set_executable(&context, name, *executable)
                .map(|()| Completed::ExecutableSet),
        };
        self.counters.performed = self.counters.performed.saturating_add(1);
        let response = FileResponse::Answer {
            request_id: admitted.request.id,
            outcome: match result {
                Ok(completed) => ResponseOutcome::Completed(completed),
                Err(refusal) => ResponseOutcome::ServiceRefused(refusal),
            },
        };
        self.count_response(&response, Some(admitted.window), admitted.reserved);
        response
    }

    /// Gives back an admitted request without performing it, such as when it timed out
    /// in a queue or the channel is closing.
    pub fn cancel(&mut self, admitted: Admitted) -> FileResponse {
        if !self.release(&admitted) {
            return self.not_admitted(&admitted);
        }
        self.counters.cancelled = self.counters.cancelled.saturating_add(1);
        let response = FileResponse::Answer {
            request_id: admitted.request.id,
            outcome: ResponseOutcome::Cancelled,
        };
        self.count_response(&response, Some(admitted.window), admitted.reserved);
        response
    }

    /// Gives back a request whose content is still arriving, freeing its buffer; `None`
    /// when no such request is being received.
    pub fn cancel_incomplete(&mut self, request_id: RequestId) -> Option<FileResponse> {
        let receiving = self.discard(request_id)?;
        self.counters.cancelled = self.counters.cancelled.saturating_add(1);
        let response = FileResponse::Answer {
            request_id,
            outcome: ResponseOutcome::Cancelled,
        };
        self.count_response(&response, Some(receiving.window), receiving.reserved);
        Some(response)
    }

    /// Receives one message and performs the request it completes, if any: the response
    /// to send, or `None` for a buffered part or a dropped message.
    pub fn dispatch(&mut self, payload: &[u8]) -> Option<FileResponse> {
        match self.receive(payload) {
            Received::Admitted(admitted) => Some(self.perform(admitted)),
            Received::Refused(response) => Some(response),
            Received::Buffered | Received::Dropped => None,
        }
    }
}
