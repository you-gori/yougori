//! The adapter of one guest file channel: file protocol requests carried on the link's
//! file channel, served by one dispatcher per attached grant, with large bodies moved as
//! CORE-05 transfers (VM part §3.2 lines 2059–2077; §5.1 lines 2218–2232; VM-W06 line 2591;
//! VM-W14 line 2606; S2 CORE-05 row line 214; tracker S05, M12 and M06's host side).
//!
//! Sans-IO: the host's link owner feeds the adapter the file channel's [`LinkEvent`]s
//! ([`GuestFiles::is_file_event`]) and lets it queue its answers on the same [`HostLink`];
//! the adapter reads no transport, clock or file of its own. Scope, clock session and time
//! come from each grant's dispatcher, which the host built for the channel's
//! [`ChannelIdentity`]; nothing the guest sends names them.
//!
//! Backpressure follows the link's windows. A guest message's bytes are credited back to
//! the link only once the adapter has processed it; while the answers waiting for the
//! guest's credit pass [`FilesLimits::max_pending_bytes`] the adapter holds guest messages
//! back unprocessed, so the guest's receive window fills and the link holds the guest
//! back. The dispatcher's own bounds (requests in flight, buffer, bytes per window) apply
//! to every message it is given.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{Clock, ContentHasher, ContentKey, OperationId};
use crate::foundation::transfer::{
    StopReason, TransferGate, TransferRefusal, TransferSession, TransferStatus, VerifiedExtentsPort,
};
use crate::sandbox::link::{
    CancelCause, Channel, ConsumeRefusal, FileMode, GrantHandle, GuestRequest, HostLink,
    HostMessage, LinkEvent, LinkLimits, LinkName, OpenRefusalCause, StreamId,
};
use crate::sandbox_contract::file_protocol::{
    Admitted, ChannelLimits, FileDispatcher, FileResponse, GuestOperation, Received, RequestId,
    RequestPart,
};
use crate::sandbox_contract::files::GuestName;

use super::body::{
    check_binding, Body, BodyAuthority, BodyExtents, BodyFailure, BodyRequest, BodyTransfers,
};
use super::declaration::{Declaration, OperationKind};
use super::event::{BodyPhase, FilesCounters, FilesEvent};
use super::identity::{body_operation, message_room, ChannelIdentity, LinkMismatch};
use super::outbound::{OutItem, Outbound};
use super::refusal::{FilesRefusal, GrantError, SetupError, MIN_ROOM_BYTES};

/// The adapter's own bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesLimits {
    /// Answer bytes that may wait for the guest's credit before the adapter stops taking
    /// guest messages: 8 MiB, the link file channel's default window. The bytes waiting
    /// can pass it by the answer of the one message processed last.
    pub max_pending_bytes: u64,
}

impl Default for FilesLimits {
    fn default() -> Self {
        Self {
            max_pending_bytes: 8 << 20,
        }
    }
}

/// The dispatcher bounds that fit `link`'s file channel: the file protocol defaults, with
/// messages no longer than one data frame carries ([`message_room`]).
pub fn channel_limits(link: &LinkLimits) -> ChannelLimits {
    ChannelLimits {
        max_message_bytes: message_room(link),
        ..ChannelLimits::default()
    }
}

/// A grant the adapter would not attach, with its dispatcher handed back.
pub struct GrantRefused<D: Clock> {
    pub error: GrantError,
    pub dispatcher: Box<FileDispatcher<D>>,
}

impl<D: Clock> fmt::Debug for GrantRefused<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantRefused")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<D: Clock> fmt::Display for GrantRefused<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

impl<D: Clock> std::error::Error for GrantRefused<D> {}

/// A grant taken off the channel: its dispatcher, and what ending its streams and bodies
/// did. The cancels of its streams go out at the next [`GuestFiles::pump`].
pub struct RemovedGrant<D: Clock> {
    pub dispatcher: FileDispatcher<D>,
    pub events: Vec<FilesEvent>,
}

/// A view of one body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyView {
    pub operation: OperationId,
    pub object: ContentKey,
    pub declared_bytes: u64,
    /// Content bytes the host holds.
    pub held_bytes: u64,
    /// Bytes charged to the transfer's budget over all attempts.
    pub used_bytes: u64,
    pub attempt: u32,
    pub status: TransferStatus,
    /// The stream carrying it; `None` while it is interrupted.
    pub stream: Option<StreamId>,
}

/// Where a stream is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Opened; its request's first message is awaited.
    Awaiting,
    /// It carries a body whose later parts are awaited.
    Body(BodyAt),
    /// Its request is answered or it carried none; nothing more is taken from the guest.
    Answered,
}

/// Where a stream carrying a body is. On a stream that resumed the body, parts sent again
/// must rise, and those the host holds already are dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BodyAt {
    request: RequestId,
    resumed: bool,
    last_part: u32,
}

struct Stream {
    grant: GrantHandle,
    declaration: Declaration,
    phase: Phase,
    guest_ended: bool,
    end_sent: bool,
}

/// A guest message on the file channel, in the order the link delivered it.
enum Inbound {
    Open {
        stream: StreamId,
        grant: GrantHandle,
        entry: LinkName,
        mode: FileMode,
    },
    Data {
        stream: StreamId,
        bytes: Vec<u8>,
    },
    End {
        stream: StreamId,
    },
    Cancel {
        stream: StreamId,
        cause: CancelCause,
    },
}

impl Inbound {
    fn stream(&self) -> StreamId {
        match self {
            Self::Open { stream, .. }
            | Self::Data { stream, .. }
            | Self::End { stream }
            | Self::Cancel { stream, .. } => *stream,
        }
    }
}

/// What a link event is to the adapter.
enum Routed {
    Inbound(Inbound),
    /// The guest granted credit on the file channel.
    Credit,
    /// The link or its file channel is gone.
    Lost,
    /// The link dropped a stream it held half-opened.
    TimedOut(StreamId),
    /// Not the adapter's.
    Foreign {
        stream: Option<StreamId>,
        refusal: FilesRefusal,
    },
}

fn route(event: LinkEvent) -> Routed {
    let foreign = |channel: Channel| Routed::Foreign {
        stream: None,
        refusal: FilesRefusal::WrongChannel { channel },
    };
    match event {
        LinkEvent::Request(request) => match request {
            GuestRequest::OpenFile {
                stream,
                grant,
                entry,
                mode,
            } => Routed::Inbound(Inbound::Open {
                stream,
                grant,
                entry,
                mode,
            }),
            GuestRequest::Data {
                channel: Channel::File,
                stream,
                bytes,
            } => Routed::Inbound(Inbound::Data { stream, bytes }),
            GuestRequest::EndOfStream {
                channel: Channel::File,
                stream,
            } => Routed::Inbound(Inbound::End { stream }),
            GuestRequest::Cancel {
                channel: Channel::File,
                stream,
                cause,
            } => Routed::Inbound(Inbound::Cancel { stream, cause }),
            GuestRequest::WindowUpdate {
                channel: Channel::File,
                ..
            } => Routed::Credit,
            GuestRequest::Opened {
                channel: Channel::File,
                stream,
            }
            | GuestRequest::OpenRefused {
                channel: Channel::File,
                stream,
                ..
            } => Routed::Foreign {
                stream: Some(stream),
                refusal: FilesRefusal::UnexpectedAnswer { stream },
            },
            GuestRequest::Data { channel, .. }
            | GuestRequest::EndOfStream { channel, .. }
            | GuestRequest::Cancel { channel, .. }
            | GuestRequest::WindowUpdate { channel, .. }
            | GuestRequest::StreamWindowUpdate { channel, .. }
            | GuestRequest::Opened { channel, .. }
            | GuestRequest::OpenRefused { channel, .. } => foreign(channel),
            GuestRequest::OpenEgress { .. } => foreign(Channel::Egress),
            GuestRequest::Ping { .. } | GuestRequest::Pong { .. } | GuestRequest::Close { .. } => {
                foreign(Channel::Control)
            }
        },
        LinkEvent::Closed(_)
        | LinkEvent::ChannelClosed {
            channel: Channel::File,
            ..
        } => Routed::Lost,
        LinkEvent::StreamTimedOut {
            channel: Channel::File,
            stream,
            ..
        } => Routed::TimedOut(stream),
        LinkEvent::ChannelClosed { channel, .. } | LinkEvent::StreamTimedOut { channel, .. } => {
            foreign(channel)
        }
        LinkEvent::Report(_) | LinkEvent::Refused(_) => Routed::Foreign {
            stream: None,
            refusal: FilesRefusal::NotFileEvent,
        },
    }
}

fn length(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// The phase a body's transfer ended in once it is cancelled: the stop it already had,
/// such as a revocation, or the cancel.
fn end_session(session: &mut TransferSession) -> BodyPhase {
    session.cancel();
    match session.status() {
        TransferStatus::Stopped(record) if record.reason != StopReason::Cancelled => {
            BodyPhase::Stopped {
                reason: record.reason.clone(),
            }
        }
        _ => BodyPhase::Cancelled,
    }
}

fn failure_refusal(failure: BodyFailure) -> FilesRefusal {
    match failure {
        BodyFailure::Length(error) => FilesRefusal::BodyLength {
            declared: error.declared,
            seen: error.seen,
        },
        BodyFailure::Transfer(refusal) => FilesRefusal::Transfer(refusal),
    }
}

/// The guest file channel of one VM instance and boot generation (VM-W14 over VM-W06).
///
/// It follows one link at a time. The host gives it a link's closing event, or calls
/// [`GuestFiles::link_lost`], before it hands it that link's successor, and never hands it
/// a replaced link again. Should the host miss the closing event, the adapter still notices
/// the new link by its lower guest sequence or a repeated stream id and ends the old link's
/// streams first, so streams of two links never mix; a replaced link handed back later is
/// taken as lost in the same way, which ends its successor's streams and interrupts their
/// bodies rather than mixing them.
pub struct GuestFiles<D: Clock> {
    identity: ChannelIdentity,
    link_limits: LinkLimits,
    room: u64,
    limits: FilesLimits,
    grants: BTreeMap<GrantHandle, FileDispatcher<D>>,
    streams: BTreeMap<StreamId, Stream>,
    bodies: BTreeMap<(GrantHandle, RequestId), Body>,
    gate: TransferGate,
    authority: Arc<dyn BodyAuthority>,
    extents: Arc<BodyExtents>,
    outbound: Outbound,
    inbound: VecDeque<Inbound>,
    owed_credit: u64,
    attached: bool,
    highest_stream: u32,
    last_sequence: u64,
    next_body: u64,
    counters: FilesCounters,
}

impl<D: Clock> fmt::Debug for GuestFiles<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestFiles")
            .field("identity", &self.identity)
            .field("grants", &self.grants.keys().collect::<Vec<_>>())
            .field("streams", &self.streams.len())
            .field("bodies", &self.bodies.len())
            .field("pending_bytes", &self.outbound.bytes())
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

impl<D: Clock> GuestFiles<D> {
    /// The channel of `identity` over links under `link_limits`, moving bodies through
    /// `transfers`: the host's transfer key and ports, whose verified-extents port is
    /// replaced by this channel's own, and the issuer of body grants.
    pub fn new(
        identity: ChannelIdentity,
        link_limits: LinkLimits,
        transfers: BodyTransfers,
        limits: FilesLimits,
    ) -> Result<Self, SetupError> {
        link_limits.validate().map_err(SetupError::Link)?;
        let room = message_room(&link_limits);
        if room < MIN_ROOM_BYTES {
            return Err(SetupError::MessageRoom {
                room_bytes: room,
                minimum: MIN_ROOM_BYTES,
            });
        }
        if limits.max_pending_bytes == 0 {
            return Err(SetupError::ZeroPending);
        }
        let extents = Arc::new(BodyExtents::new(
            identity.tenant.clone(),
            identity.parent.clone(),
            identity.host_end(),
        ));
        let mut ports = transfers.ports;
        ports.extents = Arc::clone(&extents) as Arc<dyn VerifiedExtentsPort>;
        Ok(Self {
            identity,
            link_limits,
            room,
            limits,
            grants: BTreeMap::new(),
            streams: BTreeMap::new(),
            bodies: BTreeMap::new(),
            gate: TransferGate::new(transfers.key, ports),
            authority: transfers.authority,
            extents,
            outbound: Outbound::default(),
            inbound: VecDeque::new(),
            owed_credit: 0,
            attached: false,
            highest_stream: 0,
            last_sequence: 0,
            next_body: 0,
            counters: FilesCounters::default(),
        })
    }

    pub fn identity(&self) -> &ChannelIdentity {
        &self.identity
    }

    pub fn counters(&self) -> FilesCounters {
        self.counters
    }

    /// The grant handles attached.
    pub fn grants(&self) -> impl Iterator<Item = GrantHandle> + '_ {
        self.grants.keys().copied()
    }

    pub fn dispatcher(&self, grant: GrantHandle) -> Option<&FileDispatcher<D>> {
        self.grants.get(&grant)
    }

    /// Streams the adapter holds.
    pub fn streams(&self) -> usize {
        self.streams.len()
    }

    /// Answer bytes waiting for the guest's credit.
    pub fn pending_bytes(&self) -> u64 {
        self.outbound.bytes()
    }

    /// Guest messages held back while answers wait for credit.
    pub fn deferred(&self) -> usize {
        self.inbound.len()
    }

    /// The body of `request` under `grant`, if one is moving or interrupted.
    pub fn body(&self, grant: GrantHandle, request: RequestId) -> Option<BodyView> {
        self.bodies.get(&(grant, request)).map(|body| BodyView {
            operation: body.operation.clone(),
            object: body.object,
            declared_bytes: body.declared,
            held_bytes: body.held,
            used_bytes: body.session.used_bytes(),
            attempt: body.session.attempt(),
            status: body.session.status().clone(),
            stream: body.stream,
        })
    }

    /// Attaches `dispatcher` as `grant`'s. It must be made for the channel's scope, and
    /// its messages must fit one data frame of the file channel ([`channel_limits`]).
    pub fn add_grant(
        &mut self,
        grant: GrantHandle,
        dispatcher: FileDispatcher<D>,
    ) -> Result<(), GrantRefused<D>> {
        let refused = |error, dispatcher| GrantRefused {
            error,
            dispatcher: Box::new(dispatcher),
        };
        if self.grants.contains_key(&grant) {
            return Err(refused(GrantError::Duplicate { grant }, dispatcher));
        }
        if dispatcher.scope() != self.identity.scope {
            return Err(refused(GrantError::ScopeMismatch, dispatcher));
        }
        let bound = dispatcher.limits().max_message_bytes;
        if bound > self.room {
            return Err(refused(
                GrantError::MessageBound {
                    bound_bytes: bound,
                    room_bytes: self.room,
                },
                dispatcher,
            ));
        }
        self.grants.insert(grant, dispatcher);
        Ok(())
    }

    /// Takes `grant` off the channel: its streams are cancelled as revoked, its bodies,
    /// moving or interrupted, are cancelled, and its dispatcher is handed back.
    pub fn remove_grant(&mut self, grant: GrantHandle) -> Option<RemovedGrant<D>> {
        if !self.grants.contains_key(&grant) {
            return None;
        }
        let mut events = Vec::new();
        let streams: Vec<StreamId> = self
            .streams
            .iter()
            .filter(|(_, state)| state.grant == grant)
            .map(|(stream, _)| *stream)
            .collect();
        for stream in streams {
            self.host_cancel(stream, CancelCause::Revoked, &mut events);
        }
        let bodies: Vec<(GrantHandle, RequestId)> = self
            .bodies
            .keys()
            .filter(|(owner, _)| *owner == grant)
            .copied()
            .collect();
        for key in bodies {
            self.end_body(key, &mut events);
        }
        let dispatcher = self.grants.remove(&grant)?;
        Some(RemovedGrant { dispatcher, events })
    }

    /// Whether the host should give `event` to this adapter: stream and credit events of
    /// the file channel, its closure, and the link's closure.
    pub fn is_file_event(event: &LinkEvent) -> bool {
        match event {
            LinkEvent::Request(request) => match request {
                GuestRequest::OpenFile { .. } => true,
                GuestRequest::Data { channel, .. }
                | GuestRequest::EndOfStream { channel, .. }
                | GuestRequest::Cancel { channel, .. }
                | GuestRequest::WindowUpdate { channel, .. }
                | GuestRequest::StreamWindowUpdate { channel, .. }
                | GuestRequest::Opened { channel, .. }
                | GuestRequest::OpenRefused { channel, .. } => *channel == Channel::File,
                GuestRequest::OpenEgress { .. }
                | GuestRequest::Ping { .. }
                | GuestRequest::Pong { .. }
                | GuestRequest::Close { .. } => false,
            },
            LinkEvent::Closed(_) => true,
            LinkEvent::ChannelClosed { channel, .. }
            | LinkEvent::StreamTimedOut { channel, .. } => *channel == Channel::File,
            LinkEvent::Report(_) | LinkEvent::Refused(_) => false,
        }
    }

    /// Takes one event of `link`, which must be bound to the channel's VM instance and
    /// boot generation and run under its limits, then sends what the link takes now. A
    /// link of another instance or boot is refused and nothing changes.
    pub fn handle<L: Clock>(
        &mut self,
        link: &mut HostLink<L>,
        event: LinkEvent,
    ) -> Result<Vec<FilesEvent>, LinkMismatch> {
        let mut events = Vec::new();
        self.attach(link, &mut events)?;
        match route(event) {
            Routed::Inbound(inbound) => {
                if self.paused() || !self.inbound.is_empty() {
                    self.counters.deferred = self.counters.deferred.saturating_add(1);
                    self.inbound.push_back(inbound);
                } else {
                    self.process(inbound, &mut events);
                }
            }
            Routed::Credit => {}
            Routed::Lost => self.lose(&mut events),
            Routed::TimedOut(stream) => {
                self.inbound.retain(|inbound| inbound.stream() != stream);
                let grant = self.drop_stream(stream, &mut events);
                self.refuse(
                    grant,
                    Some(stream),
                    FilesRefusal::OpenTimedOut { stream },
                    &mut events,
                );
            }
            Routed::Foreign { stream, refusal } => self.refuse(None, stream, refusal, &mut events),
        }
        self.drain(link, &mut events);
        self.last_sequence = link.last_received_sequence();
        Ok(events)
    }

    /// Sends what `link` takes now, credits processed guest bytes back to it, and takes
    /// the guest messages held back once answers fit the bound again.
    pub fn pump<L: Clock>(
        &mut self,
        link: &mut HostLink<L>,
    ) -> Result<Vec<FilesEvent>, LinkMismatch> {
        let mut events = Vec::new();
        self.attach(link, &mut events)?;
        self.drain(link, &mut events);
        self.last_sequence = link.last_received_sequence();
        Ok(events)
    }

    /// Checks every body's transfer for revocation and expiry, so a stop is acted on even
    /// while no part moves (INT-02): a stopped body is ended, and its stream, if any, is
    /// cancelled at the next [`GuestFiles::pump`].
    pub fn tick(&mut self) -> Vec<FilesEvent> {
        let mut events = Vec::new();
        let stopped: Vec<((GrantHandle, RequestId), Option<StreamId>, StopReason)> = self
            .bodies
            .iter_mut()
            .filter_map(|(key, body)| match body.session.poll() {
                TransferStatus::Stopped(record) => Some((*key, body.stream, record.reason.clone())),
                _ => None,
            })
            .collect();
        for (key, stream, reason) in stopped {
            self.end_body(key, &mut events);
            if let Some(stream) = stream {
                self.refuse_stream(
                    stream,
                    FilesRefusal::Transfer(TransferRefusal::Stopped { reason }),
                    &mut events,
                );
            }
        }
        events
    }

    /// The host cancels `stream`, and its body if it carries one; the cancel goes out at
    /// the next [`GuestFiles::pump`].
    pub fn cancel(&mut self, stream: StreamId) -> Vec<FilesEvent> {
        let mut events = Vec::new();
        self.host_cancel(stream, CancelCause::Requested, &mut events);
        events
    }

    /// Ends an interrupted body, releasing its reservation and what the host holds.
    pub fn cancel_interrupted(
        &mut self,
        grant: GrantHandle,
        request: RequestId,
    ) -> Vec<FilesEvent> {
        let mut events = Vec::new();
        let key = (grant, request);
        if self
            .bodies
            .get(&key)
            .is_some_and(|body| body.stream.is_none())
        {
            self.end_body(key, &mut events);
        }
        events
    }

    /// The host's transport reports the link gone without a closing event.
    pub fn link_lost(&mut self) -> Vec<FilesEvent> {
        let mut events = Vec::new();
        self.lose(&mut events);
        events
    }

    fn paused(&self) -> bool {
        self.outbound.bytes() >= self.limits.max_pending_bytes
    }

    /// Checks `link`'s identity and limits, and notices a new link: the old one closed, or
    /// its guest sequence starts again.
    fn attach<L: Clock>(
        &mut self,
        link: &HostLink<L>,
        events: &mut Vec<FilesEvent>,
    ) -> Result<(), LinkMismatch> {
        self.identity.check(link.binding())?;
        if *link.limits() != self.link_limits {
            return Err(LinkMismatch::OtherLimits);
        }
        if self.attached && (link.is_closed() || link.last_received_sequence() < self.last_sequence)
        {
            self.lose(events);
        }
        if !link.is_closed() {
            self.attached = true;
        }
        Ok(())
    }

    /// Credits, sends and takes held-back messages until nothing moves.
    fn drain<L: Clock>(&mut self, link: &mut HostLink<L>, events: &mut Vec<FilesEvent>) {
        loop {
            self.credit(link);
            let flushed = self.outbound.flush(link);
            for stream in flushed.ended {
                if let Some(state) = self.streams.get_mut(&stream) {
                    state.end_sent = true;
                    if state.guest_ended {
                        self.streams.remove(&stream);
                    }
                }
            }
            for (stream, refusal) in flushed.dropped {
                self.drop_stream(stream, events);
                events.push(FilesEvent::Undelivered { stream, refusal });
            }
            let mut processed = false;
            while !self.paused() {
                let Some(next) = self.inbound.pop_front() else {
                    break;
                };
                self.process(next, events);
                processed = true;
            }
            if !processed {
                return;
            }
        }
    }

    /// Returns the bytes of processed guest messages to the link's receive window.
    fn credit<L: Clock>(&mut self, link: &mut HostLink<L>) {
        if self.owed_credit == 0 {
            return;
        }
        // The link buffered every byte the adapter processed; should it hold fewer, only
        // what it holds can be returned.
        let buffered = link.channel(Channel::File).buffered_bytes;
        self.owed_credit = self.owed_credit.min(buffered);
        let amount = self.owed_credit.min(u64::from(u32::MAX));
        let Ok(credit) = u32::try_from(amount) else {
            return;
        };
        if credit == 0 {
            return;
        }
        match link.consume(Channel::File, credit) {
            Ok(()) => {
                self.owed_credit = self.owed_credit.saturating_sub(amount);
                self.counters.credited_bytes = self.counters.credited_bytes.saturating_add(amount);
            }
            // The link's file queue is full; the credit goes with the next pump.
            Err(ConsumeRefusal::QueueFull { .. }) => {}
            Err(_) => self.owed_credit = 0,
        }
    }

    fn process(&mut self, inbound: Inbound, events: &mut Vec<FilesEvent>) {
        match inbound {
            Inbound::Open {
                stream,
                grant,
                entry,
                mode,
            } => self.open(stream, grant, &entry, mode, events),
            Inbound::Data { stream, bytes } => self.data(stream, &bytes, events),
            Inbound::End { stream } => self.guest_end(stream, events),
            Inbound::Cancel { stream, cause } => {
                if let Some(grant) = self.drop_stream(stream, events) {
                    self.counters.guest_cancels = self.counters.guest_cancels.saturating_add(1);
                    events.push(FilesEvent::GuestCancelled {
                        grant,
                        stream,
                        cause,
                    });
                }
            }
        }
    }

    fn refuse(
        &mut self,
        grant: Option<GrantHandle>,
        stream: Option<StreamId>,
        refusal: FilesRefusal,
        events: &mut Vec<FilesEvent>,
    ) {
        self.counters.refusals = self.counters.refusals.saturating_add(1);
        events.push(FilesEvent::Refused {
            grant,
            stream,
            refusal,
        });
    }

    /// Cancels a stream the adapter holds, with its body, for `refusal`.
    fn refuse_stream(
        &mut self,
        stream: StreamId,
        refusal: FilesRefusal,
        events: &mut Vec<FilesEvent>,
    ) {
        let cause = refusal.cancel_cause();
        let grant = self.drop_stream(stream, events);
        if grant.is_some() {
            self.outbound.push_control(HostMessage::Cancel {
                channel: Channel::File,
                stream,
                cause,
            });
        }
        self.refuse(grant, Some(stream), refusal, events);
    }

    fn host_cancel(&mut self, stream: StreamId, cause: CancelCause, events: &mut Vec<FilesEvent>) {
        if let Some(grant) = self.drop_stream(stream, events) {
            self.outbound.push_control(HostMessage::Cancel {
                channel: Channel::File,
                stream,
                cause,
            });
            self.counters.host_cancels = self.counters.host_cancels.saturating_add(1);
            events.push(FilesEvent::HostCancelled {
                grant,
                stream,
                cause,
            });
        }
    }

    /// Forgets a stream and what waits for it, and ends the body it carries.
    fn drop_stream(
        &mut self,
        stream: StreamId,
        events: &mut Vec<FilesEvent>,
    ) -> Option<GrantHandle> {
        let state = self.streams.remove(&stream)?;
        self.outbound.forget(stream);
        if let Phase::Body(at) = state.phase {
            self.end_body((state.grant, at.request), events);
        }
        Some(state.grant)
    }

    /// Ends a body: the dispatcher gives up what it holds, the transfer is cancelled and
    /// its reservation released.
    fn end_body(&mut self, key: (GrantHandle, RequestId), events: &mut Vec<FilesEvent>) {
        let Some(mut body) = self.bodies.remove(&key) else {
            return;
        };
        self.discard_incomplete(key.0, key.1);
        let phase = end_session(&mut body.session);
        self.counters.bodies_ended = self.counters.bodies_ended.saturating_add(1);
        events.push(FilesEvent::Body {
            grant: key.0,
            request: key.1,
            operation: body.operation,
            phase,
        });
    }

    /// The dispatcher gives up a request whose content is still arriving; its answer is
    /// not sent, since the stream is cancelled or answered otherwise.
    fn discard_incomplete(&mut self, grant: GrantHandle, request: RequestId) {
        if let Some(dispatcher) = self.grants.get_mut(&grant) {
            let _ = dispatcher.cancel_incomplete(request);
        }
    }

    fn receive(&mut self, grant: GrantHandle, bytes: &[u8]) -> Option<Received> {
        self.grants
            .get_mut(&grant)
            .map(|dispatcher| dispatcher.receive(bytes))
    }

    /// Lost link: every stream ends, every body moving on it is interrupted and kept, and
    /// nothing queued for the link is sent.
    fn lose(&mut self, events: &mut Vec<FilesEvent>) {
        if !self.attached
            && self.streams.is_empty()
            && self.outbound.is_empty()
            && self.inbound.is_empty()
        {
            return;
        }
        let moving: Vec<(GrantHandle, RequestId)> = self
            .bodies
            .iter()
            .filter(|(_, body)| body.stream.is_some())
            .map(|(key, _)| *key)
            .collect();
        for key in moving {
            let interrupted = self.bodies.get_mut(&key).map(|body| {
                body.stream = None;
                (body.session.interrupt(), body.held, body.operation.clone())
            });
            match interrupted {
                Some((Ok(()), held_bytes, operation)) => {
                    self.counters.bodies_interrupted =
                        self.counters.bodies_interrupted.saturating_add(1);
                    events.push(FilesEvent::Body {
                        grant: key.0,
                        request: key.1,
                        operation,
                        phase: BodyPhase::Interrupted { held_bytes },
                    });
                }
                // The transfer had stopped, as on a revocation; nothing is kept.
                Some((Err(_), _, _)) => self.end_body(key, events),
                None => {}
            }
        }
        self.streams.clear();
        self.outbound.clear();
        self.inbound.clear();
        self.owed_credit = 0;
        self.highest_stream = 0;
        self.last_sequence = 0;
        self.attached = false;
        self.counters.links_lost = self.counters.links_lost.saturating_add(1);
        events.push(FilesEvent::LinkLost);
    }

    fn open(
        &mut self,
        stream: StreamId,
        grant: GrantHandle,
        entry: &LinkName,
        mode: FileMode,
        events: &mut Vec<FilesEvent>,
    ) {
        if stream.get() <= self.highest_stream {
            // The link never repeats a guest stream id, so this is a new link, and the
            // messages held back behind this one came on it too.
            let later = std::mem::take(&mut self.inbound);
            self.lose(events);
            self.inbound = later;
            self.attached = true;
        }
        self.highest_stream = stream.get();
        let refused = if self.grants.contains_key(&grant) {
            match Declaration::parse(entry, mode) {
                Ok(declaration) => {
                    self.streams.insert(
                        stream,
                        Stream {
                            grant,
                            declaration,
                            phase: Phase::Awaiting,
                            guest_ended: false,
                            end_sent: false,
                        },
                    );
                    self.outbound.push(stream, OutItem::Opened);
                    self.counters.opened = self.counters.opened.saturating_add(1);
                    events.push(FilesEvent::Opened { grant, stream });
                    return;
                }
                Err(refusal) => (
                    OpenRefusalCause::Unsupported,
                    FilesRefusal::Declaration(refusal),
                ),
            }
        } else {
            (
                OpenRefusalCause::NotAuthorized,
                FilesRefusal::UnknownGrant { grant },
            )
        };
        self.counters.open_refusals = self.counters.open_refusals.saturating_add(1);
        self.outbound.push_control(HostMessage::OpenRefused {
            channel: Channel::File,
            stream,
            cause: refused.0,
        });
        self.refuse(Some(grant), Some(stream), refused.1, events);
    }

    fn data(&mut self, stream: StreamId, bytes: &[u8], events: &mut Vec<FilesEvent>) {
        self.owed_credit = self.owed_credit.saturating_add(length(bytes));
        let Some((grant, declaration, phase)) = self
            .streams
            .get(&stream)
            .map(|state| (state.grant, state.declaration, state.phase))
        else {
            return self.refuse(
                None,
                Some(stream),
                FilesRefusal::UnknownStream { stream },
                events,
            );
        };
        match phase {
            Phase::Answered => self.refuse_stream(stream, FilesRefusal::AfterAnswer, events),
            Phase::Awaiting => self.first(stream, grant, declaration, bytes, events),
            Phase::Body(at) => self.part(stream, grant, at, bytes, events),
        }
    }

    /// The first message of a stream: its request, or a part resuming an interrupted body.
    fn first(
        &mut self,
        stream: StreamId,
        grant: GrantHandle,
        declaration: Declaration,
        bytes: &[u8],
        events: &mut Vec<FilesEvent>,
    ) {
        let decoded = match RequestPart::decode(bytes) {
            // The dispatcher answers with its own refusal.
            Err(_) => return self.whole(stream, grant, None, bytes, events),
            Ok(decoded) => decoded,
        };
        let (id, operation, declared) = match decoded {
            RequestPart::Opening {
                id,
                operation,
                declared_length,
            } => (id, operation, declared_length),
            RequestPart::Continuation { id, .. } => {
                let resumes = matches!(declaration, Declaration::Content { content }
                if self.bodies.get(&(grant, id)).is_some_and(|body| {
                    body.stream.is_none() && body.object == content
                }));
                if !resumes {
                    return self.refuse_stream(
                        stream,
                        FilesRefusal::NoRequest { claimed: id },
                        events,
                    );
                }
                if self.resume(stream, grant, id, events) {
                    let at = BodyAt {
                        request: id,
                        resumed: true,
                        last_part: 0,
                    };
                    self.part(stream, grant, at, bytes, events);
                }
                return;
            }
        };
        if let Err(refusal) = declaration.admits(&operation) {
            return self.refuse_stream(stream, FilesRefusal::Declaration(refusal), events);
        }
        let Declaration::Content { content: object } = declaration else {
            return self.whole(stream, grant, Some(id), bytes, events);
        };
        let (kind, name, first) = match &operation {
            GuestOperation::Create { name, content }
            | GuestOperation::Write { name, content }
            | GuestOperation::UploadWrite { name, content, .. } => (
                OperationKind::of(&operation),
                name.clone(),
                content.as_slice(),
            ),
            _ => return self.refuse_stream(stream, FilesRefusal::Disagreement, events),
        };
        let resumes = self.bodies.get(&(grant, id)).is_some_and(|body| {
            body.stream.is_none()
                && body.object == object
                && body.kind == kind
                && body.name == name
                && body.declared == declared
        });
        if resumes {
            if self.resume(stream, grant, id, events) {
                self.counters.resent_parts_dropped =
                    self.counters.resent_parts_dropped.saturating_add(1);
            }
            return;
        }
        if declared == length(first) {
            let received = ContentKey::of(first);
            if received != object {
                return self.refuse_stream(
                    stream,
                    FilesRefusal::ContentMismatch {
                        declared: object,
                        received,
                    },
                    events,
                );
            }
            return self.whole(stream, grant, Some(id), bytes, events);
        }
        match self.receive(grant, bytes) {
            Some(Received::Buffered) => {
                let body = NewBody {
                    request: id,
                    kind,
                    name,
                    object,
                    declared,
                };
                self.open_body(stream, grant, body, first, events);
            }
            Some(Received::Refused(response)) => self.answer(stream, grant, response, events),
            Some(Received::Dropped) => {
                self.refuse_stream(stream, FilesRefusal::WindowSpent, events)
            }
            Some(Received::Admitted(admitted)) => {
                if let Some(dispatcher) = self.grants.get_mut(&grant) {
                    let _ = dispatcher.cancel(admitted);
                }
                self.refuse_stream(stream, FilesRefusal::Disagreement, events);
            }
            None => self.refuse_stream(stream, FilesRefusal::UnknownGrant { grant }, events),
        }
    }

    /// A request that is whole in its first message: performed, or answered with the
    /// dispatcher's refusal.
    fn whole(
        &mut self,
        stream: StreamId,
        grant: GrantHandle,
        id: Option<RequestId>,
        bytes: &[u8],
        events: &mut Vec<FilesEvent>,
    ) {
        match self.receive(grant, bytes) {
            Some(Received::Admitted(admitted)) => self.perform(stream, grant, admitted, events),
            Some(Received::Refused(response)) => self.answer(stream, grant, response, events),
            Some(Received::Dropped) => {
                self.refuse_stream(stream, FilesRefusal::WindowSpent, events)
            }
            Some(Received::Buffered) => {
                if let Some(id) = id {
                    self.discard_incomplete(grant, id);
                }
                self.refuse_stream(stream, FilesRefusal::Disagreement, events);
            }
            None => self.refuse_stream(stream, FilesRefusal::UnknownGrant { grant }, events),
        }
    }

    fn perform(
        &mut self,
        stream: StreamId,
        grant: GrantHandle,
        admitted: Admitted,
        events: &mut Vec<FilesEvent>,
    ) {
        let Some(dispatcher) = self.grants.get_mut(&grant) else {
            return self.refuse_stream(stream, FilesRefusal::UnknownGrant { grant }, events);
        };
        let request = admitted.request().id;
        let response = dispatcher.perform(admitted);
        self.counters.performed = self.counters.performed.saturating_add(1);
        events.push(FilesEvent::Performed {
            grant,
            stream,
            request,
        });
        self.answer(stream, grant, response, events);
    }

    /// Queues `response` and the end of the stream.
    fn answer(
        &mut self,
        stream: StreamId,
        grant: GrantHandle,
        response: FileResponse,
        events: &mut Vec<FilesEvent>,
    ) {
        if !self.streams.contains_key(&stream) {
            return;
        }
        if let FileResponse::Refusal { refusal, .. } = &response {
            self.counters.protocol_refusals = self.counters.protocol_refusals.saturating_add(1);
            events.push(FilesEvent::ProtocolRefused {
                grant,
                stream,
                refusal: refusal.clone(),
            });
        }
        let Some(dispatcher) = self.grants.get(&grant) else {
            return self.refuse_stream(stream, FilesRefusal::UnknownGrant { grant }, events);
        };
        match dispatcher.encode(&response) {
            Ok(messages) => {
                for message in messages {
                    self.outbound.push(stream, OutItem::Data(message));
                }
                self.outbound.push(stream, OutItem::End);
                if let Some(state) = self.streams.get_mut(&stream) {
                    state.phase = Phase::Answered;
                }
            }
            Err(error) => self.refuse_stream(stream, FilesRefusal::Encode(error), events),
        }
    }

    /// Opens the CORE-05 transfer of a body whose first part the dispatcher holds, and
    /// keeps that part's content under it.
    fn open_body(
        &mut self,
        stream: StreamId,
        grant: GrantHandle,
        new: NewBody,
        first: &[u8],
        events: &mut Vec<FilesEvent>,
    ) {
        let id = new.request;
        self.next_body = self.next_body.saturating_add(1);
        let operation = match body_operation(&self.identity.operation, grant, self.next_body) {
            Ok(operation) => operation,
            Err(error) => {
                self.discard_incomplete(grant, id);
                return self.refuse_stream(stream, FilesRefusal::OperationName(error), events);
            }
        };
        let request = BodyRequest {
            operation: operation.clone(),
            tenant: self.identity.tenant.clone(),
            parent: self.identity.parent.clone(),
            grant,
            request: id,
            kind: new.kind,
            name: new.name.clone(),
            object: new.object,
            length_bytes: new.declared,
            source: self.identity.guest_end(grant),
            recipient: self.identity.host_end(),
        };
        let opened = self
            .authority
            .authorize(&request)
            .map_err(FilesRefusal::Authority)
            .and_then(|sealed| {
                let envelope = self.gate.verify(&sealed).map_err(FilesRefusal::Transfer)?;
                check_binding(envelope, &request, self.room)
                    .map_err(|field| FilesRefusal::NotBound { field })?;
                self.gate
                    .open(&sealed, &request.connection())
                    .map_err(FilesRefusal::Transfer)
            });
        let session = match opened {
            Ok(session) => session,
            Err(refusal) => {
                self.discard_incomplete(grant, id);
                return self.refuse_stream(stream, refusal, events);
            }
        };
        let mut body = Body {
            operation: operation.clone(),
            object: new.object,
            kind: new.kind,
            name: new.name,
            declared: new.declared,
            held: 0,
            next_part: 0,
            hasher: ContentHasher::new(new.declared),
            session,
            connection: request.connection(),
            stream: Some(stream),
        };
        self.counters.bodies_opened = self.counters.bodies_opened.saturating_add(1);
        events.push(FilesEvent::Body {
            grant,
            request: id,
            operation: operation.clone(),
            phase: BodyPhase::Opened {
                length_bytes: new.declared,
            },
        });
        if let Err(failure) = body.take(0, first) {
            let phase = end_session(&mut body.session);
            self.discard_incomplete(grant, id);
            self.counters.bodies_ended = self.counters.bodies_ended.saturating_add(1);
            events.push(FilesEvent::Body {
                grant,
                request: id,
                operation,
                phase,
            });
            return self.refuse_stream(stream, failure_refusal(failure), events);
        }
        self.bodies.insert((grant, id), body);
        if let Some(state) = self.streams.get_mut(&stream) {
            state.phase = Phase::Body(BodyAt {
                request: id,
                resumed: false,
                last_part: 0,
            });
        }
    }

    /// Continues an interrupted body on `stream` in a new attempt of its transfer.
    fn resume(
        &mut self,
        stream: StreamId,
        grant: GrantHandle,
        id: RequestId,
        events: &mut Vec<FilesEvent>,
    ) -> bool {
        let key = (grant, id);
        let Some(body) = self.bodies.get_mut(&key) else {
            return false;
        };
        match body.session.retry(&body.connection) {
            Ok(()) => {
                body.stream = Some(stream);
                let phase = BodyPhase::Resumed {
                    attempt: body.session.attempt(),
                    held_bytes: body.held,
                };
                let operation = body.operation.clone();
                if let Some(state) = self.streams.get_mut(&stream) {
                    state.phase = Phase::Body(BodyAt {
                        request: id,
                        resumed: true,
                        last_part: 0,
                    });
                }
                self.counters.bodies_resumed = self.counters.bodies_resumed.saturating_add(1);
                events.push(FilesEvent::Body {
                    grant,
                    request: id,
                    operation,
                    phase,
                });
                true
            }
            Err(refusal) => {
                self.end_body(key, events);
                self.refuse_stream(stream, FilesRefusal::Transfer(refusal), events);
                false
            }
        }
    }

    /// A later message on a stream carrying a body.
    fn part(
        &mut self,
        stream: StreamId,
        grant: GrantHandle,
        at: BodyAt,
        bytes: &[u8],
        events: &mut Vec<FilesEvent>,
    ) {
        let BodyAt {
            request,
            resumed,
            last_part,
        } = at;
        let key = (grant, request);
        let (id, part, content) = match RequestPart::decode(bytes) {
            Err(_) => {
                return match self.receive(grant, bytes) {
                    Some(Received::Refused(response)) => {
                        self.end_body(key, events);
                        self.answer(stream, grant, response, events);
                    }
                    Some(Received::Dropped) => {
                        self.refuse_stream(stream, FilesRefusal::WindowSpent, events)
                    }
                    Some(Received::Admitted(admitted)) => {
                        if let Some(dispatcher) = self.grants.get_mut(&grant) {
                            let _ = dispatcher.cancel(admitted);
                        }
                        self.refuse_stream(stream, FilesRefusal::Disagreement, events);
                    }
                    Some(Received::Buffered) | None => {
                        self.refuse_stream(stream, FilesRefusal::Disagreement, events)
                    }
                };
            }
            Ok(RequestPart::Opening { .. }) => {
                return self.refuse_stream(stream, FilesRefusal::SecondRequest, events)
            }
            Ok(RequestPart::Continuation { id, part, content }) => (id, part, content),
        };
        if id != request {
            return self.refuse_stream(
                stream,
                FilesRefusal::OtherRequest {
                    expected: request,
                    claimed: id,
                },
                events,
            );
        }
        let Some(next_part) = self.bodies.get(&key).map(|body| body.next_part) else {
            return self.refuse_stream(stream, FilesRefusal::Disagreement, events);
        };
        if resumed {
            if part <= last_part {
                return self.refuse_stream(
                    stream,
                    FilesRefusal::PartNotIncreasing {
                        part,
                        last: last_part,
                    },
                    events,
                );
            }
            if let Some(state) = self.streams.get_mut(&stream) {
                state.phase = Phase::Body(BodyAt {
                    last_part: part,
                    ..at
                });
            }
            if part < next_part {
                self.counters.resent_parts_dropped =
                    self.counters.resent_parts_dropped.saturating_add(1);
                return;
            }
        }
        match self.receive(grant, bytes) {
            Some(Received::Buffered) => {
                let taken = self
                    .bodies
                    .get_mut(&key)
                    .map(|body| body.take(part, &content));
                match taken {
                    Some(Ok(())) => {}
                    Some(Err(failure)) => {
                        self.end_body(key, events);
                        self.refuse_stream(stream, failure_refusal(failure), events);
                    }
                    None => self.refuse_stream(stream, FilesRefusal::Disagreement, events),
                }
            }
            Some(Received::Admitted(admitted)) => {
                self.complete(stream, key, part, &content, admitted, events)
            }
            Some(Received::Refused(response)) => {
                self.end_body(key, events);
                self.answer(stream, grant, response, events);
            }
            Some(Received::Dropped) => {
                self.refuse_stream(stream, FilesRefusal::WindowSpent, events)
            }
            None => self.refuse_stream(stream, FilesRefusal::UnknownGrant { grant }, events),
        }
    }

    /// The last part of a body: kept, the whole content checked against its declared key,
    /// the transfer completed, then the request performed.
    fn complete(
        &mut self,
        stream: StreamId,
        key: (GrantHandle, RequestId),
        part: u32,
        content: &[u8],
        admitted: Admitted,
        events: &mut Vec<FilesEvent>,
    ) {
        let (grant, request) = key;
        let Some(mut body) = self.bodies.remove(&key) else {
            if let Some(dispatcher) = self.grants.get_mut(&grant) {
                let _ = dispatcher.cancel(admitted);
            }
            return self.refuse_stream(stream, FilesRefusal::Disagreement, events);
        };
        let checked = body
            .take(part, content)
            .map_err(failure_refusal)
            .and_then(|()| {
                let hasher = std::mem::replace(&mut body.hasher, ContentHasher::new(0));
                hasher.finish().map_err(|error| FilesRefusal::BodyLength {
                    declared: error.declared,
                    seen: error.seen,
                })
            })
            .and_then(|received| {
                if received == body.object {
                    Ok(())
                } else {
                    Err(FilesRefusal::ContentMismatch {
                        declared: body.object,
                        received,
                    })
                }
            })
            .and_then(|()| {
                self.extents.record(body.object, body.declared);
                let finished = body.session.finish();
                self.extents.forget(&body.object);
                finished.map_err(FilesRefusal::Transfer)
            });
        match checked {
            Ok(()) => {
                self.counters.bodies_completed = self.counters.bodies_completed.saturating_add(1);
                events.push(FilesEvent::Body {
                    grant,
                    request,
                    operation: body.operation,
                    phase: BodyPhase::Completed {
                        length_bytes: body.declared,
                    },
                });
                self.perform(stream, grant, admitted, events);
            }
            Err(refusal) => {
                if let Some(dispatcher) = self.grants.get_mut(&grant) {
                    let _ = dispatcher.cancel(admitted);
                }
                let phase = match &refusal {
                    FilesRefusal::ContentMismatch { declared, received } => {
                        body.session.cancel();
                        BodyPhase::Mismatched {
                            declared: *declared,
                            received: *received,
                        }
                    }
                    _ => end_session(&mut body.session),
                };
                self.counters.bodies_ended = self.counters.bodies_ended.saturating_add(1);
                events.push(FilesEvent::Body {
                    grant,
                    request,
                    operation: body.operation,
                    phase,
                });
                self.refuse_stream(stream, refusal, events);
            }
        }
    }

    fn guest_end(&mut self, stream: StreamId, events: &mut Vec<FilesEvent>) {
        let Some((grant, phase, end_sent)) = self.streams.get_mut(&stream).map(|state| {
            state.guest_ended = true;
            (state.grant, state.phase, state.end_sent)
        }) else {
            return;
        };
        match phase {
            Phase::Awaiting => {
                self.outbound.push(stream, OutItem::End);
                if let Some(state) = self.streams.get_mut(&stream) {
                    state.phase = Phase::Answered;
                }
            }
            Phase::Body(at) => {
                let (held_bytes, declared_bytes) = self
                    .bodies
                    .get(&(grant, at.request))
                    .map_or((0, 0), |body| (body.held, body.declared));
                self.refuse_stream(
                    stream,
                    FilesRefusal::BodyEndedEarly {
                        held_bytes,
                        declared_bytes,
                    },
                    events,
                );
            }
            Phase::Answered => {
                if end_sent {
                    self.streams.remove(&stream);
                }
            }
        }
    }
}

/// A body about to be opened.
struct NewBody {
    request: RequestId,
    kind: OperationKind,
    name: GuestName,
    object: ContentKey,
    declared: u64,
}
