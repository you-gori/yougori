//! The guest-opened egress streams of one boot's link (M06's guest transport for the relay;
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §3.1: the guest's HTTP goes to
//! the confined relay as plaintext per guest connection; VM-W11). The counterpart of
//! [`terminal`](super::terminal) for the egress channel.
//!
//! The guest opens an egress stream to a named destination (`StreamOpen::Egress`). While an
//! egress port is attached to the boot ([`EgressStreams::set_accepting`]), the host accepts the
//! open and hands every byte the guest sends to the port as an [`EgressEvent`]; the port's
//! bytes go back on the stream through [`EgressStreams::write`], chunked to the channel's
//! message bound and its send credit, and the host ends its direction with
//! [`EgressStreams::end`]. Without a port every open is refused `Unavailable`. The channel
//! is flow-controlled per stream (protocol version 3, module docs of `link`): bytes the guest
//! sent on a stream of the port are credited back to that stream at once, as the port takes
//! them; the host's bytes go out within each stream's own credit, so a guest program that
//! stops reading holds back only its stream. Pending host-to-guest bytes are bounded per
//! stream ([`MAX_PENDING_BYTES`]); a write beyond the bound is refused, which is the port's
//! backpressure.
//!
//! The host parses nothing here: the bytes are the guest's and the relay's, moved as they
//! are. Where they go (the relay process, over the guest pipe) is the port's.
//!
//! A boot may also have sandbox connection endpoints (M14, [`EgressStreams::set_connections`]):
//! an open naming one is accepted with or without a port, and its bytes are credited back
//! only as the connection's other end takes them ([`EgressStreams::consumed`]), so the guest
//! sends no faster than that end reads. Each stream has a window of its own, so a connection
//! whose other end does not read stops only itself: the boot's other egress streams keep
//! their own credit.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::foundation::ids::{Clock, MonotonicTime};
use crate::sandbox::link::{
    CancelCause, Channel, CloseCause, GuestRequest, HostLink, HostMessage, LinkEvent, LinkName,
    OpenRefusalCause, SendRefusal, StreamId, FIELD_OVERHEAD_BYTES,
};

use super::log::ClosureCause;

/// The most host-to-guest bytes one egress stream holds pending; a write beyond it is
/// refused until the link took some.
pub const MAX_PENDING_BYTES: usize = 1 << 20;

/// What happened on the egress channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressEvent {
    /// The guest opened `stream` to `destination` and the host accepted it.
    Opened {
        stream: StreamId,
        destination: LinkName,
    },
    /// Bytes the guest sent on an open stream.
    Data { stream: StreamId, bytes: Vec<u8> },
    /// The guest ended its direction; the host may still write.
    GuestEnded { stream: StreamId },
    /// The stream is gone on both directions or was cut.
    Ended {
        stream: StreamId,
        cause: EgressEndCause,
    },
    /// The guest's open was refused: no port is attached.
    Refused {
        stream: StreamId,
        destination: LinkName,
        unsent: Option<SendRefusal>,
    },
}

/// Why an egress stream ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressEndCause {
    /// Both directions ended in order.
    Finished,
    /// The guest cancelled the stream.
    GuestCancelled { cancel: CancelCause },
    /// The host cancelled the stream (the port asked).
    HostCancelled,
    /// The link closed.
    LinkClosed { close: CloseCause },
    /// The host closed the boot's channels.
    HostClosed { closure: ClosureCause },
}

/// Why a port's write or end was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressRefusal {
    UnknownStream { stream: StreamId },
    /// The stream holds [`MAX_PENDING_BYTES`] already; write again once the link took some.
    PendingFull { stream: StreamId, pending: usize },
    /// The host already ended its direction.
    HostEnded { stream: StreamId },
}

impl fmt::Display for EgressRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownStream { stream } => write!(f, "egress stream {stream:?} is not open"),
            Self::PendingFull { stream, pending } => write!(
                f,
                "egress stream {stream:?} holds {pending} pending bytes, the bound"
            ),
            Self::HostEnded { stream } => {
                write!(f, "the host ended its direction of egress stream {stream:?}")
            }
        }
    }
}

impl std::error::Error for EgressRefusal {}

struct EgressStream {
    stream: StreamId,
    pending: VecDeque<u8>,
    end_requested: bool,
    host_ended: bool,
    guest_ended: bool,
    /// A sandbox connection's stream: its bytes are credited as they are consumed.
    deferred: bool,
    /// Of a deferred stream's bytes, those not consumed yet.
    uncredited: u64,
    /// The guest's bytes taken and not credited back to the stream yet.
    owed: u64,
}

/// The egress streams of one boot's link (module docs).
pub(super) struct EgressStreams {
    accepting: bool,
    /// The boot's sandbox connection endpoints.
    connections: BTreeSet<LinkName>,
    open: BTreeMap<u32, EgressStream>,
    events: Vec<EgressEvent>,
}

impl fmt::Debug for EgressStreams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressStreams")
            .field("accepting", &self.accepting)
            .field("open", &self.open.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl EgressStreams {
    pub(super) fn new() -> Self {
        Self {
            accepting: false,
            connections: BTreeSet::new(),
            open: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    /// Whether guest opens are accepted (a port is attached).
    pub(super) fn set_accepting(&mut self, accepting: bool) {
        self.accepting = accepting;
    }

    /// The boot's sandbox connection endpoints: opens naming one are accepted whether or not
    /// a port is attached, and credited as consumed.
    pub(super) fn set_connections(&mut self, names: BTreeSet<LinkName>) {
        self.connections = names;
    }

    /// `bytes` of deferred `stream`'s data were taken by the connection's other end: their
    /// credit is due to the guest. A stream already gone needs none: its window went with it.
    pub(super) fn consumed(&mut self, stream: StreamId, bytes: u64) {
        if let Some(open) = self.open.get_mut(&stream.get()) {
            let bytes = bytes.min(open.uncredited);
            open.uncredited -= bytes;
            open.owed = open.owed.saturating_add(bytes);
        }
    }

    /// Forgets `stream`; its window goes with it, so nothing is credited.
    fn forget(&mut self, stream: StreamId) -> Option<EgressStream> {
        self.open.remove(&stream.get())
    }

    pub(super) fn is_accepting(&self) -> bool {
        self.accepting
    }

    pub(super) fn open_streams(&self) -> usize {
        self.open.len()
    }

    pub(super) fn take_events(&mut self) -> Vec<EgressEvent> {
        std::mem::take(&mut self.events)
    }

    /// Takes one of `link`'s events: the egress channel's are used here, every other event
    /// is handed back.
    pub(super) fn handle<C: Clock>(
        &mut self,
        link: &mut HostLink<C>,
        event: LinkEvent,
        _now: MonotonicTime,
    ) -> Option<LinkEvent> {
        match event {
            LinkEvent::Request(GuestRequest::OpenEgress {
                stream,
                destination,
            }) => {
                let connection = self.connections.contains(&destination);
                if !(self.accepting || connection) || self.open.contains_key(&stream.get()) {
                    let unsent = link
                        .send(HostMessage::OpenRefused {
                            channel: Channel::Egress,
                            stream,
                            cause: OpenRefusalCause::Unavailable,
                        })
                        .err();
                    self.events.push(EgressEvent::Refused {
                        stream,
                        destination,
                        unsent,
                    });
                    return None;
                }
                match link.send(HostMessage::Opened {
                    channel: Channel::Egress,
                    stream,
                }) {
                    Ok(()) => {
                        self.open.insert(
                            stream.get(),
                            EgressStream {
                                stream,
                                pending: VecDeque::new(),
                                end_requested: false,
                                host_ended: false,
                                guest_ended: false,
                                deferred: connection,
                                uncredited: 0,
                                owed: 0,
                            },
                        );
                        self.events.push(EgressEvent::Opened {
                            stream,
                            destination,
                        });
                    }
                    Err(unsent) => self.events.push(EgressEvent::Refused {
                        stream,
                        destination,
                        unsent: Some(unsent),
                    }),
                }
                None
            }
            LinkEvent::Request(GuestRequest::Data {
                channel: Channel::Egress,
                stream,
                bytes,
            }) => {
                let length = bytes.len() as u64;
                // A stream gone needs no credit: its window went with it.
                if let Some(open) = self.open.get_mut(&stream.get()) {
                    if open.deferred {
                        open.uncredited = open.uncredited.saturating_add(length);
                    } else {
                        open.owed = open.owed.saturating_add(length);
                    }
                    self.events.push(EgressEvent::Data { stream, bytes });
                }
                None
            }
            // The guest's credit for a stream: the next pump writes within it.
            LinkEvent::Request(GuestRequest::StreamWindowUpdate {
                channel: Channel::Egress,
                ..
            }) => None,
            LinkEvent::Request(GuestRequest::EndOfStream {
                channel: Channel::Egress,
                stream,
            }) => {
                if let Some(open) = self.open.get_mut(&stream.get()) {
                    open.guest_ended = true;
                    let finished = open.host_ended;
                    self.events.push(EgressEvent::GuestEnded { stream });
                    if finished {
                        self.forget(stream);
                        self.events.push(EgressEvent::Ended {
                            stream,
                            cause: EgressEndCause::Finished,
                        });
                    }
                }
                None
            }
            LinkEvent::Request(GuestRequest::Cancel {
                channel: Channel::Egress,
                stream,
                cause,
            }) => {
                if self.forget(stream).is_some() {
                    self.events.push(EgressEvent::Ended {
                        stream,
                        cause: EgressEndCause::GuestCancelled { cancel: cause },
                    });
                }
                None
            }
            other => Some(other),
        }
    }

    pub(super) fn send_room(&self, stream: StreamId) -> usize {
        self.open.get(&stream.get()).filter(|s| !s.host_ended && !s.end_requested)
            .map_or(0, |s| MAX_PENDING_BYTES.saturating_sub(s.pending.len()))
    }

    /// Queues `bytes` for the guest on `stream`; they go out as the link takes them.
    pub(super) fn write(&mut self, stream: StreamId, bytes: &[u8]) -> Result<(), EgressRefusal> {
        let open = self
            .open
            .get_mut(&stream.get())
            .ok_or(EgressRefusal::UnknownStream { stream })?;
        if open.host_ended || open.end_requested {
            return Err(EgressRefusal::HostEnded { stream });
        }
        if open.pending.len().saturating_add(bytes.len()) > MAX_PENDING_BYTES {
            return Err(EgressRefusal::PendingFull {
                stream,
                pending: open.pending.len(),
            });
        }
        open.pending.extend(bytes);
        Ok(())
    }

    /// Ends the host's direction of `stream` once its pending bytes went out.
    pub(super) fn end(&mut self, stream: StreamId) -> Result<(), EgressRefusal> {
        let open = self
            .open
            .get_mut(&stream.get())
            .ok_or(EgressRefusal::UnknownStream { stream })?;
        if open.host_ended {
            return Err(EgressRefusal::HostEnded { stream });
        }
        open.end_requested = true;
        Ok(())
    }

    /// Cancels `stream` on the link (the port's side failed); the stream is gone.
    pub(super) fn cancel<C: Clock>(
        &mut self,
        link: &mut HostLink<C>,
        stream: StreamId,
    ) -> Result<Option<SendRefusal>, EgressRefusal> {
        self.forget(stream)
            .ok_or(EgressRefusal::UnknownStream { stream })?;
        let unsent = link
            .send(HostMessage::Cancel {
                channel: Channel::Egress,
                stream,
                cause: CancelCause::Requested,
            })
            .err();
        self.events.push(EgressEvent::Ended {
            stream,
            cause: EgressEndCause::HostCancelled,
        });
        Ok(unsent)
    }

    /// Cancels every open stream of the port on the link (the port detached); each ends
    /// `HostCancelled`. Sandbox connections' streams are not the port's and stay.
    pub(super) fn cancel_relayed<C: Clock>(&mut self, link: &mut HostLink<C>) {
        let streams: Vec<StreamId> = self
            .open
            .values()
            .filter(|open| !open.deferred)
            .map(|open| open.stream)
            .collect();
        for stream in streams {
            let _ = self.cancel(link, stream);
        }
    }

    /// Credits each stream the guest's bytes taken from it and writes what the link takes
    /// now, each stream within its own credit.
    pub(super) fn pump<C: Clock>(&mut self, link: &mut HostLink<C>) {
        let chunk = usize::try_from(link.limits().quota(Channel::Egress).max_message_bytes)
            .unwrap_or(usize::MAX)
            .saturating_sub(FIELD_OVERHEAD_BYTES);
        let mut finished = Vec::new();
        for open in self.open.values_mut() {
            while open.owed > 0 {
                let credit = u32::try_from(open.owed).unwrap_or(u32::MAX);
                match link.consume_stream(Channel::Egress, open.stream, credit) {
                    Ok(()) => open.owed -= u64::from(credit),
                    Err(_) => open.owed = 0,
                }
            }
            if open.host_ended {
                continue;
            }
            loop {
                if open.pending.is_empty() {
                    if open.end_requested
                        && link
                            .send(HostMessage::EndOfStream {
                                channel: Channel::Egress,
                                stream: open.stream,
                            })
                            .is_ok()
                    {
                        open.host_ended = true;
                        if open.guest_ended {
                            finished.push(open.stream);
                        }
                    }
                    break;
                }
                let credit = usize::try_from(link.stream_send_credit(Channel::Egress, open.stream))
                    .unwrap_or(usize::MAX);
                let take = open.pending.len().min(chunk).min(credit);
                if take == 0 {
                    break;
                }
                let bytes: Vec<u8> = open.pending.iter().take(take).copied().collect();
                match link.send(HostMessage::Data {
                    channel: Channel::Egress,
                    stream: open.stream,
                    bytes,
                }) {
                    Ok(()) => {
                        open.pending.drain(..take);
                    }
                    Err(_) => break,
                }
            }
        }
        for stream in finished {
            self.forget(stream);
            self.events.push(EgressEvent::Ended {
                stream,
                cause: EgressEndCause::Finished,
            });
        }
    }

    /// Ends every stream with `cause`; the events wait for the next route (the link was
    /// replaced).
    pub(super) fn end_all_later(&mut self, cause: EgressEndCause) {
        let streams: Vec<StreamId> = self.open.values().map(|open| open.stream).collect();
        self.open.clear();
        self.events
            .extend(streams.into_iter().map(|stream| EgressEvent::Ended {
                stream,
                cause: cause.clone(),
            }));
    }

    /// Ends every stream with `cause` (the host closed the channels); every pending event
    /// is returned now.
    pub(super) fn end_all(&mut self, cause: EgressEndCause) -> Vec<EgressEvent> {
        self.end_all_later(cause);
        self.take_events()
    }
}
