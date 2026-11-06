//! The host-opened ingress streams of one boot's link (M14's guest transport; docs/combined-
//! gpu-memory-and-vm-sandbox-plan.md, VM part §4.7: a caller reaches a guest service only
//! through a live publication; VM-W13). The counterpart of [`egress`](super::egress), opened
//! from the other side.
//!
//! Once the connection gate admitted a caller, the host opens an ingress stream to a guest
//! listener (`port-N`: the guest agent dials its own `127.0.0.1:N`) and the guest answers
//! `Opened` once its service accepted, or `OpenRefused`. Bytes queued for the guest before
//! the answer wait; afterwards they go out chunked to the channel's message bound and the
//! stream's own credit (the channel is flow-controlled per stream, protocol version 3), and
//! the host ends its direction with [`IngressStreams::end`]. Every byte the guest sends is
//! handed on as an [`IngressEvent`] and credited back to its stream only once its caller took
//! it ([`IngressStreams::consumed`]), so a guest never sends faster than its callers read, the
//! host holds at most each stream's window of its bytes, and a caller that stops reading
//! stops only its own stream. Pending host-to-guest bytes are bounded per stream
//! ([`MAX_PENDING_BYTES`]); a write beyond the bound is refused, which is the caller's
//! backpressure.
//!
//! The host parses nothing here: the bytes are the caller's and the guest service's, moved
//! as they are.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use crate::foundation::ids::{Clock, MonotonicTime};
use crate::sandbox::link::{
    CancelCause, Channel, ChannelCloseCause, CloseCause, GuestRequest, HostLink, HostMessage,
    LinkEvent, LinkName, OpenRefusalCause, SendRefusal, StreamId, FIELD_OVERHEAD_BYTES,
};

use super::egress::MAX_PENDING_BYTES;
use super::log::ClosureCause;

/// What happened on the ingress channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressEvent {
    /// The guest's service accepted the stream.
    Opened { stream: StreamId },
    /// The guest refused the open (nothing listens there, or no stream may open now).
    Refused {
        stream: StreamId,
        cause: OpenRefusalCause,
    },
    /// Bytes the guest's service sent on an open stream.
    Data { stream: StreamId, bytes: Vec<u8> },
    /// The guest ended its direction; the host may still write.
    GuestEnded { stream: StreamId },
    /// The stream is gone on both directions or was cut.
    Ended {
        stream: StreamId,
        cause: IngressEndCause,
    },
}

/// Why an ingress stream ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressEndCause {
    /// Both directions ended in order.
    Finished,
    /// The guest cancelled the stream.
    GuestCancelled { cancel: CancelCause },
    /// The host cancelled the stream (its caller went away or was closed).
    HostCancelled,
    /// The guest never answered the open in time.
    OpenTimedOut,
    /// The ingress channel closed.
    ChannelClosed { cause: ChannelCloseCause },
    /// The link closed.
    LinkClosed { close: CloseCause },
    /// The host closed the boot's channels.
    HostClosed { closure: ClosureCause },
}

/// Why an open, a write or an end was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressRefusal {
    /// No stream id is left on this link.
    StreamIdsExhausted,
    /// The open could not be sent.
    Send(SendRefusal),
    UnknownStream { stream: StreamId },
    /// The stream holds [`MAX_PENDING_BYTES`] already; write again once the link took some.
    PendingFull { stream: StreamId, pending: usize },
    /// The host already ended its direction.
    HostEnded { stream: StreamId },
}

impl fmt::Display for IngressRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StreamIdsExhausted => f.write_str("no ingress stream id is left on this link"),
            Self::Send(refusal) => write!(f, "the ingress open could not be sent: {refusal:?}"),
            Self::UnknownStream { stream } => write!(f, "ingress stream {stream:?} is not open"),
            Self::PendingFull { stream, pending } => write!(
                f,
                "ingress stream {stream:?} holds {pending} pending bytes, the bound"
            ),
            Self::HostEnded { stream } => {
                write!(f, "the host ended its direction of ingress stream {stream:?}")
            }
        }
    }
}

impl std::error::Error for IngressRefusal {}

struct IngressStream {
    stream: StreamId,
    /// The guest answered `Opened`.
    opened: bool,
    pending: VecDeque<u8>,
    end_requested: bool,
    host_ended: bool,
    guest_ended: bool,
    /// The guest's bytes received and not taken by the caller yet.
    uncredited: u64,
    /// Of the guest's bytes, those the caller took and not credited back yet.
    owed: u64,
}

/// The ingress streams of one boot's link (module docs).
pub(super) struct IngressStreams {
    /// The next host-opened stream id (even, rising).
    next_stream: Option<u32>,
    open: BTreeMap<u32, IngressStream>,
    events: Vec<IngressEvent>,
}

impl fmt::Debug for IngressStreams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IngressStreams")
            .field("open", &self.open.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl IngressStreams {
    pub(super) fn new() -> Self {
        Self {
            next_stream: Some(2),
            open: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    pub(super) fn open_streams(&self) -> usize {
        self.open.len()
    }

    pub(super) fn take_events(&mut self) -> Vec<IngressEvent> {
        std::mem::take(&mut self.events)
    }

    /// Opens a stream to the guest's `listener`; it is usable once the guest answers
    /// ([`IngressEvent::Opened`]), and bytes written meanwhile wait.
    pub(super) fn open<C: Clock>(
        &mut self,
        link: &mut HostLink<C>,
        listener: LinkName,
    ) -> Result<StreamId, IngressRefusal> {
        let stream = self
            .next_stream
            .and_then(StreamId::new)
            .ok_or(IngressRefusal::StreamIdsExhausted)?;
        link.send(HostMessage::OpenIngress { stream, listener })
            .map_err(IngressRefusal::Send)?;
        self.next_stream = stream.get().checked_add(2);
        self.open.insert(
            stream.get(),
            IngressStream {
                stream,
                opened: false,
                pending: VecDeque::new(),
                end_requested: false,
                host_ended: false,
                guest_ended: false,
                uncredited: 0,
                owed: 0,
            },
        );
        Ok(stream)
    }

    /// Takes one of `link`'s events: the ingress channel's are used here, every other event
    /// is handed back.
    pub(super) fn handle<C: Clock>(
        &mut self,
        _link: &mut HostLink<C>,
        event: LinkEvent,
        _now: MonotonicTime,
    ) -> Option<LinkEvent> {
        match event {
            LinkEvent::Request(GuestRequest::Opened {
                channel: Channel::Ingress,
                stream,
            }) => {
                if let Some(open) = self.open.get_mut(&stream.get()) {
                    open.opened = true;
                    self.events.push(IngressEvent::Opened { stream });
                }
                None
            }
            LinkEvent::Request(GuestRequest::OpenRefused {
                channel: Channel::Ingress,
                stream,
                cause,
            }) => {
                if self.open.remove(&stream.get()).is_some() {
                    self.events.push(IngressEvent::Refused { stream, cause });
                }
                None
            }
            LinkEvent::Request(GuestRequest::Data {
                channel: Channel::Ingress,
                stream,
                bytes,
            }) => {
                let length = bytes.len() as u64;
                // A stream gone needs no credit: its window went with it.
                if let Some(open) = self.open.get_mut(&stream.get()) {
                    open.uncredited = open.uncredited.saturating_add(length);
                    self.events.push(IngressEvent::Data { stream, bytes });
                }
                None
            }
            // The guest's credit for a stream: the next pump writes within it.
            LinkEvent::Request(GuestRequest::StreamWindowUpdate {
                channel: Channel::Ingress,
                ..
            }) => None,
            LinkEvent::Request(GuestRequest::EndOfStream {
                channel: Channel::Ingress,
                stream,
            }) => {
                if let Some(open) = self.open.get_mut(&stream.get()) {
                    open.guest_ended = true;
                    self.events.push(IngressEvent::GuestEnded { stream });
                    if open.host_ended {
                        self.open.remove(&stream.get());
                        self.events.push(IngressEvent::Ended {
                            stream,
                            cause: IngressEndCause::Finished,
                        });
                    }
                }
                None
            }
            LinkEvent::Request(GuestRequest::Cancel {
                channel: Channel::Ingress,
                stream,
                cause,
            }) => {
                if self.open.remove(&stream.get()).is_some() {
                    self.events.push(IngressEvent::Ended {
                        stream,
                        cause: IngressEndCause::GuestCancelled { cancel: cause },
                    });
                }
                None
            }
            LinkEvent::StreamTimedOut {
                channel: Channel::Ingress,
                stream,
                ..
            } => {
                if self.open.remove(&stream.get()).is_some() {
                    self.events.push(IngressEvent::Ended {
                        stream,
                        cause: IngressEndCause::OpenTimedOut,
                    });
                }
                None
            }
            LinkEvent::ChannelClosed {
                channel: Channel::Ingress,
                cause,
            } => {
                self.end_all_later(IngressEndCause::ChannelClosed { cause });
                Some(LinkEvent::ChannelClosed {
                    channel: Channel::Ingress,
                    cause,
                })
            }
            LinkEvent::Closed(cause) => {
                self.end_all_later(IngressEndCause::LinkClosed {
                    close: cause.clone(),
                });
                Some(LinkEvent::Closed(cause))
            }
            other => Some(other),
        }
    }

    /// Queues `bytes` for the guest on `stream`; they go out as the link takes them, once
    /// the guest answered the open.
    pub(super) fn write(&mut self, stream: StreamId, bytes: &[u8]) -> Result<(), IngressRefusal> {
        let open = self
            .open
            .get_mut(&stream.get())
            .ok_or(IngressRefusal::UnknownStream { stream })?;
        if open.host_ended || open.end_requested {
            return Err(IngressRefusal::HostEnded { stream });
        }
        if open.pending.len().saturating_add(bytes.len()) > MAX_PENDING_BYTES {
            return Err(IngressRefusal::PendingFull {
                stream,
                pending: open.pending.len(),
            });
        }
        open.pending.extend(bytes);
        Ok(())
    }

    /// Ends the host's direction of `stream` once its pending bytes went out.
    pub(super) fn end(&mut self, stream: StreamId) -> Result<(), IngressRefusal> {
        let open = self
            .open
            .get_mut(&stream.get())
            .ok_or(IngressRefusal::UnknownStream { stream })?;
        if open.host_ended {
            return Err(IngressRefusal::HostEnded { stream });
        }
        open.end_requested = true;
        Ok(())
    }

    /// Cancels `stream` on the link (its caller went away); the stream is gone.
    pub(super) fn cancel<C: Clock>(
        &mut self,
        link: &mut HostLink<C>,
        stream: StreamId,
    ) -> Result<Option<SendRefusal>, IngressRefusal> {
        self.open
            .remove(&stream.get())
            .ok_or(IngressRefusal::UnknownStream { stream })?;
        let unsent = link
            .send(HostMessage::Cancel {
                channel: Channel::Ingress,
                stream,
                cause: CancelCause::Requested,
            })
            .err();
        self.events.push(IngressEvent::Ended {
            stream,
            cause: IngressEndCause::HostCancelled,
        });
        Ok(unsent)
    }

    /// `bytes` of `stream`'s guest bytes were taken by its caller (or never will be): their
    /// credit goes back to the stream at the next pump. A stream gone needs none.
    pub(super) fn consumed(&mut self, stream: StreamId, bytes: u64) {
        if let Some(open) = self.open.get_mut(&stream.get()) {
            let bytes = bytes.min(open.uncredited);
            open.uncredited -= bytes;
            open.owed = open.owed.saturating_add(bytes);
        }
    }

    /// Credits each stream the bytes its caller took and writes what the link takes now,
    /// each stream within its own credit.
    pub(super) fn pump<C: Clock>(&mut self, link: &mut HostLink<C>) {
        let chunk = usize::try_from(link.limits().quota(Channel::Ingress).max_message_bytes)
            .unwrap_or(usize::MAX)
            .saturating_sub(FIELD_OVERHEAD_BYTES);
        let mut finished = Vec::new();
        for open in self.open.values_mut() {
            while open.owed > 0 {
                let credit = u32::try_from(open.owed).unwrap_or(u32::MAX);
                match link.consume_stream(Channel::Ingress, open.stream, credit) {
                    Ok(()) => open.owed -= u64::from(credit),
                    Err(_) => open.owed = 0,
                }
            }
            if open.host_ended || !open.opened {
                continue;
            }
            loop {
                if open.pending.is_empty() {
                    if open.end_requested
                        && link
                            .send(HostMessage::EndOfStream {
                                channel: Channel::Ingress,
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
                let credit =
                    usize::try_from(link.stream_send_credit(Channel::Ingress, open.stream))
                        .unwrap_or(usize::MAX);
                let take = open.pending.len().min(chunk).min(credit);
                if take == 0 {
                    break;
                }
                let bytes: Vec<u8> = open.pending.iter().take(take).copied().collect();
                match link.send(HostMessage::Data {
                    channel: Channel::Ingress,
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
            self.open.remove(&stream.get());
            self.events.push(IngressEvent::Ended {
                stream,
                cause: IngressEndCause::Finished,
            });
        }
    }

    /// Ends every stream with `cause`; the events wait for the next route (the link was
    /// replaced or closed).
    pub(super) fn end_all_later(&mut self, cause: IngressEndCause) {
        let streams: Vec<StreamId> = self.open.values().map(|open| open.stream).collect();
        self.open.clear();
        self.events
            .extend(streams.into_iter().map(|stream| IngressEvent::Ended {
                stream,
                cause: cause.clone(),
            }));
    }

    /// Ends every stream with `cause` (the host closed the channels); every pending event
    /// is returned now.
    pub(super) fn end_all(&mut self, cause: IngressEndCause) -> Vec<IngressEvent> {
        self.end_all_later(cause);
        self.take_events()
    }
}
